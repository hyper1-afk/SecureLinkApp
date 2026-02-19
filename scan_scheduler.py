"""
Scan Scheduler - Background service that runs scheduled domain scans.
Uses threading + schedule library (same pattern as weekly_reports.py).

Copyright (c) 2026 SecureLink. All rights reserved.
"""
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

import schedule

from config import Config
from domain_scanner import DomainScanner
from attack_surface_db import AttackSurfaceDB

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Background service that scans domains on their configured schedule."""

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.scanner = DomainScanner(config)
        self.db = AttackSurfaceDB(config)
        self._running = False
        self._thread: Optional[threading.Thread] = None

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
            scan_result=result
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

        # Alert: SSL expiring within 14 days
        days_until_expiry = result.ssl_info.get('days_until_expiry')
        if days_until_expiry is not None and 0 < days_until_expiry <= 14:
            self.db.create_alert(
                monitored_domain_id=domain_id,
                user_id=user_id,
                alert_type='ssl_expiry',
                title=f'SSL certificate for {domain} expires in {days_until_expiry} days',
                message=f'The SSL certificate for {domain} will expire in {days_until_expiry} day(s). '
                        f'Renew it before visitors see browser warnings.',
                severity='high' if days_until_expiry <= 7 else 'medium'
            )

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
