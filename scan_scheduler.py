"""
Scan Scheduler - Background service that runs scheduled domain scans.
Uses threading + schedule library (same pattern as weekly_reports.py).

Copyright (c) 2026 SecureLink. All rights reserved.
"""
import logging
import smtplib
import threading
import time
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import schedule

from config import Config
from domain_scanner import DomainScanner, DANGEROUS_PORTS
from attack_surface_db import AttackSurfaceDB
from database import Database

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Background service that scans domains on their configured schedule."""

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.scanner = DomainScanner(config)
        self.db = AttackSurfaceDB(config)
        self.main_db = Database(config)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._health_watch_last_run: Optional[str] = None

    def start(self):
        """Start the scheduler in a background thread"""
        if self._running:
            logger.warning("Scan scheduler is already running")
            return

        self._running = True

        # Schedule the check every 15 minutes
        schedule.every(15).minutes.do(self._run_due_scans)

        self._thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._thread.start()
        logger.info("Scan scheduler started (checking every 15 minutes)")

    def stop(self):
        """Stop the scheduler"""
        self._running = False
        schedule.clear()
        logger.info("Scan scheduler stopped")

    def _scheduler_loop(self):
        """Main scheduler loop running in background thread"""
        # Run once immediately on start
        self._run_due_scans()

        while self._running:
            schedule.run_pending()
            time.sleep(30)  # Check every 30 seconds

    def _run_due_scans(self):
        """Find and run all scans that are currently due"""
        try:
            due_domains = self.db.get_domains_due_for_scan()
            if not due_domains:
                return

            logger.info(f"Running scheduled scans for {len(due_domains)} domain(s)")

            for domain_info in due_domains:
                try:
                    self._scan_domain(domain_info)
                except Exception as e:
                    logger.error(f"Error scanning {domain_info.get('domain')}: {e}")

        except Exception as e:
            logger.error(f"Scheduler error: {e}")

        self._run_due_health_watches()

    def _scan_domain(self, domain_info: dict):
        """Run a scan for a single domain and save results"""
        domain = domain_info['domain']
        domain_id = domain_info['id']
        user_id = domain_info['user_id']
        previous_score = domain_info.get('latest_score')

        logger.info(f"Scheduled scan starting for: {domain}")
        result = self.scanner.scan_domain(domain)

        # Save scan record
        scan_id = self.db.save_scan(
            monitored_domain_id=domain_id,
            user_id=user_id,
            scan_result=result,
            scan_source='scheduled'
        )

        # Check for alert conditions
        self._check_alerts(domain_info, result, previous_score)

        logger.info(f"Scheduled scan complete for {domain}: score={result.score}, grade={result.grade}")

    def _check_alerts(self, domain_info: dict, result, previous_score: Optional[int]):
        """Check scan results against alert conditions and create alerts"""
        domain_id = domain_info['id']
        user_id = domain_info['user_id']
        domain = domain_info['domain']

        # Alert: score dropped significantly (10+ points)
        if previous_score is not None and result.score < previous_score - 10:
            drop = previous_score - result.score
            self.db.create_alert(
                monitored_domain_id=domain_id,
                user_id=user_id,
                alert_type='score_drop',
                title=f'Security score dropped {drop} points for {domain}',
                message=f'The security score for {domain} dropped from {previous_score} to {result.score} '
                        f'(grade: {result.grade}). Review the latest scan for new findings.',
                severity='high' if drop >= 20 else 'medium'
            )

        # Alert: critical findings detected
        critical_count = sum(1 for f in result.findings if f.severity == 'critical')
        if critical_count > 0 and domain_info.get('notify_on_critical', True):
            self.db.create_alert(
                monitored_domain_id=domain_id,
                user_id=user_id,
                alert_type='critical_finding',
                title=f'{critical_count} critical finding(s) for {domain}',
                message=f'{critical_count} critical security issue(s) detected on {domain}. '
                        f'These require immediate attention.',
                severity='critical'
            )

        # Alert: SSL expiring within 30 days
        days_until_expiry = result.ssl_info.get('days_until_expiry') if result.ssl_info else None
        if days_until_expiry is not None and days_until_expiry <= 30:
            if days_until_expiry <= 0:
                ssl_severity = 'critical'
                ssl_title = f'SSL certificate for {domain} has EXPIRED'
                ssl_msg = (f'The SSL certificate for {domain} has expired. '
                           f'Visitors will see browser security warnings immediately.')
            elif days_until_expiry <= 7:
                ssl_severity = 'high'
                ssl_title = f'SSL certificate for {domain} expires in {days_until_expiry} days'
                ssl_msg = (f'The SSL certificate for {domain} will expire in {days_until_expiry} day(s). '
                           f'Renew it immediately to avoid browser warnings.')
            else:
                ssl_severity = 'medium'
                ssl_title = f'SSL certificate for {domain} expires in {days_until_expiry} days'
                ssl_msg = (f'The SSL certificate for {domain} will expire in {days_until_expiry} day(s). '
                           f'Renew it before visitors see browser warnings.')

            self.db.create_alert(
                monitored_domain_id=domain_id,
                user_id=user_id,
                alert_type='ssl_expiry',
                title=ssl_title,
                message=ssl_msg,
                severity=ssl_severity
            )
            self._send_expiry_alert_email(user_id, domain, 'ssl_expiry', days_until_expiry, ssl_severity)

        # Alert: domain registration expiring within 30 days
        whois_info = result.whois_info or {}
        domain_days = whois_info.get('days_until_domain_expiry')
        if domain_days is not None and domain_days <= 30:
            if domain_days <= 0:
                dom_severity = 'critical'
                dom_title = f'Domain registration for {domain} has EXPIRED'
                dom_msg = (f'The domain registration for {domain} has expired. '
                           f'Your domain may be suspended or taken over.')
            elif domain_days <= 7:
                dom_severity = 'high'
                dom_title = f'Domain registration for {domain} expires in {domain_days} days'
                dom_msg = (f'The domain registration for {domain} expires in {domain_days} day(s). '
                           f'Renew immediately to prevent service interruption.')
            else:
                dom_severity = 'medium'
                dom_title = f'Domain registration for {domain} expires in {domain_days} days'
                dom_msg = (f'The domain registration for {domain} expires in {domain_days} day(s). '
                           f'Renew soon to avoid losing your domain.')

            self.db.create_alert(
                monitored_domain_id=domain_id,
                user_id=user_id,
                alert_type='domain_expiry',
                title=dom_title,
                message=dom_msg,
                severity=dom_severity
            )
            self._send_expiry_alert_email(user_id, domain, 'domain_expiry', domain_days, dom_severity)

        # Alert: grade dropped to D or F
        if result.grade in ('D', 'F'):
            prev_grade = domain_info.get('latest_grade')
            if prev_grade and prev_grade not in ('D', 'F'):
                self.db.create_alert(
                    monitored_domain_id=domain_id,
                    user_id=user_id,
                    alert_type='grade_drop',
                    title=f'Security grade for {domain} dropped to {result.grade}',
                    message=f'The security grade for {domain} dropped from {prev_grade} to {result.grade}. '
                            f'Multiple security issues need to be addressed.',
                    severity='high'
                )

        # ---- IDS Block 1: New open port ----
        baseline_ports = domain_info.get('baseline_ports')
        current_ports = (result.port_info or {}).get('open_ports', [])
        if baseline_ports is not None:
            for port in sorted(set(current_ports) - set(baseline_ports)):
                if self.db.has_recent_ids_alert(domain_id, 'new_port_detected', str(port)):
                    continue
                severity = 'high' if port in DANGEROUS_PORTS else 'medium'
                self.db.create_alert(
                    monitored_domain_id=domain_id,
                    user_id=user_id,
                    alert_type='new_port_detected',
                    title=f'New open port detected on {domain}: port {port}',
                    message=f'Port {port} is now open on {domain} but was not present in the baseline. '
                            f'Verify this service is intentional.',
                    severity=severity
                )
                if severity == 'high':
                    self._send_ids_alert_email(user_id, domain, 'new_port_detected',
                                               f'Port {port}', severity)

        # ---- IDS Block 2: SSL certificate change ----
        baseline_fp = domain_info.get('baseline_ssl_fingerprint')
        current_fp = (result.ssl_info or {}).get('fingerprint')
        if baseline_fp and current_fp and baseline_fp != current_fp:
            if not self.db.has_recent_ids_alert(domain_id, 'ssl_cert_changed', domain):
                self.db.create_alert(
                    monitored_domain_id=domain_id,
                    user_id=user_id,
                    alert_type='ssl_cert_changed',
                    title=f'SSL certificate changed for {domain}',
                    message=f'The SSL certificate fingerprint for {domain} has changed since the baseline. '
                            f'Verify this renewal or re-issue was authorized.',
                    severity='high'
                )
                self._send_ids_alert_email(user_id, domain, 'ssl_cert_changed',
                                           'Certificate fingerprint mismatch', 'high')

        # ---- IDS Block 3: DNS record change ----
        baseline_dns = domain_info.get('baseline_dns') or {}
        current_dns = result.dns_info or {}

        def _dns_list(records, key='host'):
            out = []
            for r in (records or []):
                out.append(r[key] if isinstance(r, dict) else str(r))
            return out

        current_dns_norm = {
            'A':   [r if isinstance(r, str) else r.get('address', str(r))
                    for r in current_dns.get('a_records', [])],
            'MX':  _dns_list(current_dns.get('mx_records', []), 'host'),
            'NS':  _dns_list(current_dns.get('ns_records', []), 'host'),
            'TXT': [r if isinstance(r, str) else r.get('text', str(r))
                    for r in current_dns.get('txt_records', [])],
        }
        for rtype in ('A', 'NS', 'MX', 'TXT'):
            base_set = set(baseline_dns.get(rtype, []))
            curr_set = set(current_dns_norm.get(rtype, []))
            if base_set and base_set != curr_set:
                if self.db.has_recent_ids_alert(domain_id, 'dns_record_changed', rtype):
                    continue
                severity = 'high' if rtype in ('A', 'NS') else 'medium'
                added   = curr_set - base_set
                removed = base_set - curr_set
                detail  = []
                if added:
                    detail.append(f'Added: {", ".join(sorted(added))}')
                if removed:
                    detail.append(f'Removed: {", ".join(sorted(removed))}')
                self.db.create_alert(
                    monitored_domain_id=domain_id,
                    user_id=user_id,
                    alert_type='dns_record_changed',
                    title=f'DNS {rtype} record changed for {domain}',
                    message=f'The {rtype} DNS records for {domain} differ from the baseline. '
                            + ' '.join(detail),
                    severity=severity
                )
                if severity == 'high':
                    self._send_ids_alert_email(user_id, domain, 'dns_record_changed',
                                               f'{rtype} record change', severity)

        # ---- IDS Block 4: Content integrity (defacement) ----
        baseline_hash = domain_info.get('baseline_content_hash')
        current_hash = getattr(result, 'content_hash', None)
        if baseline_hash and current_hash and baseline_hash != current_hash:
            if not self.db.has_recent_ids_alert(domain_id, 'content_changed', domain):
                self.db.create_alert(
                    monitored_domain_id=domain_id,
                    user_id=user_id,
                    alert_type='content_changed',
                    title=f'Website content changed for {domain}',
                    message=f'The homepage content hash for {domain} has changed since the baseline. '
                            f'Review for unauthorized modifications or defacement.',
                    severity='high'
                )
                self._send_ids_alert_email(user_id, domain, 'content_changed',
                                           'Content hash mismatch', 'high')


    def _send_expiry_alert_email(self, user_id: int, domain: str, alert_type: str,
                                    days_remaining: int, severity: str):
        """Send SSL or domain registration expiry alert email to the domain owner."""
        try:
            from auth import AuthManager
            auth = AuthManager(self.config)
            session = auth.Session()
            from auth import User
            user = session.query(User).filter_by(id=user_id).first()
            if not user:
                return
            # Respect user's email notification preference
            if not getattr(user, 'email_notifications', True):
                return
            recipient = str(getattr(user, 'notification_email', None) or user.email)
            session.close()
        except Exception as e:
            logger.error(f"Failed to look up user for expiry email: {e}")
            return

        smtp_user = getattr(self.config, 'EMAIL_USERNAME', None)
        smtp_pass = getattr(self.config, 'EMAIL_PASSWORD', None)
        if not smtp_user or not smtp_pass:
            logger.warning("SMTP credentials not configured — skipping expiry alert email")
            return

        # Severity colours
        color_map = {'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#ffc107'}
        banner_color = color_map.get(severity, '#6c757d')
        text_color = '#000' if severity == 'medium' else '#fff'

        if alert_type == 'ssl_expiry':
            subject_tag = f'[{severity.upper()}] SSL Certificate Expiring: {domain}'
            heading = 'SSL Certificate Expiry Alert'
            detail_label = 'Certificate expires'
            action = 'Renew your SSL certificate through your hosting provider or certificate authority.'
        else:
            subject_tag = f'[{severity.upper()}] Domain Registration Expiring: {domain}'
            heading = 'Domain Registration Expiry Alert'
            detail_label = 'Registration expires'
            action = 'Log in to your domain registrar and renew your domain registration immediately.'

        if days_remaining <= 0:
            expiry_text = '<strong>already expired</strong>'
        elif days_remaining == 1:
            expiry_text = 'in <strong>1 day</strong>'
        else:
            expiry_text = f'in <strong>{days_remaining} days</strong>'

        html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:20px;">
  <div style="max-width:560px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">
    <div style="background:{banner_color};padding:20px 24px;">
      <h2 style="color:{text_color};margin:0;font-size:18px;">{heading}</h2>
    </div>
    <div style="padding:24px;">
      <p style="margin:0 0 12px;font-size:15px;color:#333;">
        <strong>Domain:</strong> {domain}
      </p>
      <p style="margin:0 0 12px;font-size:15px;color:#333;">
        <strong>{detail_label}:</strong> {expiry_text}
      </p>
      <p style="margin:0 0 20px;font-size:15px;color:#555;">{action}</p>
      <a href="https://securelinkapp.com/attack-surface"
         style="display:inline-block;background:#0d6efd;color:#fff;padding:10px 20px;
                border-radius:6px;text-decoration:none;font-size:14px;">
        View Attack Surface Dashboard
      </a>
    </div>
    <div style="padding:16px 24px;background:#f8f9fa;font-size:12px;color:#888;text-align:center;">
      SecureLink Security Platform &mdash; <a href="https://securelinkapp.com" style="color:#888;">securelinkapp.com</a>
    </div>
  </div>
</body>
</html>"""

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject_tag
            msg['From'] = getattr(self.config, 'SMTP_FROM_EMAIL', 'support@securelinkapp.com')
            msg['To'] = recipient
            msg.attach(MIMEText(html_body, 'html'))

            smtp_host = getattr(self.config, 'SMTP_HOST', 'email-smtp.us-east-2.amazonaws.com')
            smtp_port = int(getattr(self.config, 'SMTP_PORT', 587))
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)

            logger.info(f"Expiry alert email sent to {recipient} for {domain} ({alert_type})")
        except Exception as e:
            logger.error(f"Failed to send expiry alert email to {recipient}: {e}")


    def _send_ids_alert_email(self, user_id: int, domain: str, alert_type: str,
                              detail: str, severity: str):
        """Send an IDS detection alert email to the domain owner."""
        try:
            from auth import AuthManager, User
            auth = AuthManager(self.config)
            session = auth.Session()
            user = session.query(User).filter_by(id=user_id).first()
            if not user:
                session.close()
                return
            if not getattr(user, 'email_notifications', True):
                session.close()
                return
            recipient = str(getattr(user, 'notification_email', None) or user.email)
            session.close()
        except Exception as e:
            logger.error(f"Failed to look up user for IDS alert email: {e}")
            return

        smtp_user = getattr(self.config, 'EMAIL_USERNAME', None)
        smtp_pass = getattr(self.config, 'EMAIL_PASSWORD', None)
        if not smtp_user or not smtp_pass:
            logger.warning("SMTP credentials not configured — skipping IDS alert email")
            return

        color_map = {'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#ffc107'}
        banner_color = color_map.get(severity, '#6c757d')
        text_color = '#000' if severity == 'medium' else '#fff'

        type_labels = {
            'new_port_detected': ('New Open Port Detected', 'A port that was not in the security baseline is now open.'),
            'ssl_cert_changed':  ('SSL Certificate Changed', 'The SSL certificate has changed since the baseline was established.'),
            'dns_record_changed': ('DNS Record Changed', 'DNS records have changed since the baseline was established.'),
            'content_changed':   ('Website Content Changed', 'The homepage content has changed — possible defacement detected.'),
        }
        heading, description = type_labels.get(alert_type, ('IDS Alert', 'A security change was detected.'))
        subject = f'[{severity.upper()}] {heading}: {domain}'

        html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:20px;">
  <div style="max-width:560px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">
    <div style="background:{banner_color};padding:20px 24px;">
      <h2 style="color:{text_color};margin:0;font-size:18px;">{heading}</h2>
    </div>
    <div style="padding:24px;">
      <p style="margin:0 0 12px;font-size:15px;color:#333;"><strong>Domain:</strong> {domain}</p>
      <p style="margin:0 0 12px;font-size:15px;color:#333;"><strong>Detail:</strong> {detail}</p>
      <p style="margin:0 0 20px;font-size:15px;color:#555;">{description}</p>
      <a href="https://securelinkapp.com/attack-surface"
         style="display:inline-block;background:#0d6efd;color:#fff;padding:10px 20px;
                border-radius:6px;text-decoration:none;font-size:14px;">
        View Attack Surface Dashboard
      </a>
    </div>
    <div style="padding:16px 24px;background:#f8f9fa;font-size:12px;color:#888;text-align:center;">
      SecureLink IDS &mdash; <a href="https://securelinkapp.com" style="color:#888;">securelinkapp.com</a>
    </div>
  </div>
</body>
</html>"""

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = getattr(self.config, 'SMTP_FROM_EMAIL', 'support@securelinkapp.com')
            msg['To'] = recipient
            msg.attach(MIMEText(html_body, 'html'))

            smtp_host = getattr(self.config, 'SMTP_HOST', 'email-smtp.us-east-2.amazonaws.com')
            smtp_port = int(getattr(self.config, 'SMTP_PORT', 587))
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)

            logger.info(f"IDS alert email sent to {recipient} for {domain} ({alert_type})")
        except Exception as e:
            logger.error(f"Failed to send IDS alert email to {recipient}: {e}")


    def _run_due_health_watches(self):
        """Daily job: check all Pro user domain watches and email on score drops."""
        from datetime import date
        today = date.today().isoformat()
        if self._health_watch_last_run == today:
            return
        try:
            watches = self.main_db.get_all_active_watches()
            if not watches:
                self._health_watch_last_run = today
                return

            logger.info(f"Running health watch checks for {len(watches)} watch(es)")
            for watch in watches:
                try:
                    domain = watch['domain']
                    user_id = watch['user_id']
                    result = self.scanner.scan_domain(domain)
                    old_score = watch.get('last_score')
                    if old_score is not None and result.score < old_score - 10:
                        self._send_health_watch_email(user_id, domain, old_score, result.score)
                    self.main_db.update_health_watch_score(user_id, domain, result.score)
                except Exception as e:
                    logger.error(f"Health watch error for {watch.get('domain')}: {e}")

            self._health_watch_last_run = today
        except Exception as e:
            logger.error(f"Health watch scheduler error: {e}")

    def _send_health_watch_email(self, user_id: int, domain: str, old_score: int, new_score: int):
        """Send score drop alert email for a watched domain (Pro feature)."""
        try:
            from auth import AuthManager, User
            auth = AuthManager(self.config)
            session = auth.Session()
            user = session.query(User).filter_by(id=user_id).first()
            if not user:
                session.close()
                return
            if not getattr(user, 'email_notifications', True):
                session.close()
                return
            recipient = str(getattr(user, 'notification_email', None) or user.email)
            session.close()
        except Exception as e:
            logger.error(f"Failed to look up user for health watch email: {e}")
            return

        smtp_user = getattr(self.config, 'EMAIL_USERNAME', None)
        smtp_pass = getattr(self.config, 'EMAIL_PASSWORD', None)
        if not smtp_user or not smtp_pass:
            logger.warning("SMTP credentials not configured — skipping health watch email")
            return

        drop = old_score - new_score
        severity = 'high' if drop >= 20 else 'medium'
        color_map = {'high': '#fd7e14', 'medium': '#ffc107'}
        banner_color = color_map.get(severity, '#6c757d')
        text_color = '#000' if severity == 'medium' else '#fff'

        # Determine grade from new score
        if new_score >= 90:
            grade = 'A'
        elif new_score >= 80:
            grade = 'B'
        elif new_score >= 70:
            grade = 'C'
        elif new_score >= 60:
            grade = 'D'
        else:
            grade = 'F'

        subject = f'[{severity.upper()}] Security score dropped for {domain}'
        html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:20px;">
  <div style="max-width:560px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">
    <div style="background:{banner_color};padding:20px 24px;">
      <h2 style="color:{text_color};margin:0;font-size:18px;">Security Score Drop Alert</h2>
    </div>
    <div style="padding:24px;">
      <p style="margin:0 0 12px;font-size:15px;color:#333;"><strong>Domain:</strong> {domain}</p>
      <p style="margin:0 0 12px;font-size:15px;color:#333;">
        <strong>Score:</strong> {old_score} &rarr; <strong>{new_score}</strong> (Grade: {grade})
      </p>
      <p style="margin:0 0 20px;font-size:15px;color:#555;">
        The security score for <strong>{domain}</strong> dropped by {drop} points.
        Run a new health check to see what changed.
      </p>
      <a href="https://securelinkapp.com/dashboard"
         style="display:inline-block;background:#0d6efd;color:#fff;padding:10px 20px;
                border-radius:6px;text-decoration:none;font-size:14px;">
        View Domain Health Check
      </a>
    </div>
    <div style="padding:16px 24px;background:#f8f9fa;font-size:12px;color:#888;text-align:center;">
      SecureLink Security Platform &mdash; <a href="https://securelinkapp.com" style="color:#888;">securelinkapp.com</a>
    </div>
  </div>
</body>
</html>"""

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = getattr(self.config, 'SMTP_FROM_EMAIL', 'support@securelinkapp.com')
            msg['To'] = recipient
            msg.attach(MIMEText(html_body, 'html'))

            smtp_host = getattr(self.config, 'SMTP_HOST', 'email-smtp.us-east-2.amazonaws.com')
            smtp_port = int(getattr(self.config, 'SMTP_PORT', 587))
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)

            logger.info(f"Health watch email sent to {recipient} for {domain} (score {old_score}→{new_score})")
        except Exception as e:
            logger.error(f"Failed to send health watch email to {recipient}: {e}")


def run_single_scan(domain: str, monitored_domain_id: int, user_id: int,
                    config: Config = None) -> dict:
    """
    Convenience function: run a single scan and save results.
    Returns the scan result as a dict.
    """
    config = config or Config()
    scanner = DomainScanner(config)
    db = AttackSurfaceDB(config)

    result = scanner.scan_domain(domain)
    scan_id = db.save_scan(
        monitored_domain_id=monitored_domain_id,
        user_id=user_id,
        scan_result=result
    )

    return result.to_dict()


# Singleton
_scheduler_instance = None

def get_scan_scheduler(config: Config = None) -> ScanScheduler:
    """Get or create the scan scheduler singleton"""
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = ScanScheduler(config)
    return _scheduler_instance
