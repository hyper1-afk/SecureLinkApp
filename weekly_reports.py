"""
Weekly Security Report Generator
Sends users email reports of threats identified and risk levels.

Copyright (c) 2026 SecureLink. All rights reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import threading
import time
import schedule

from sqlalchemy import func, and_
from config import Config
from database import Database, VerificationRecord

logger = logging.getLogger(__name__)


class WeeklyReportGenerator:
    """Generates and sends weekly security reports to users"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.db = Database(self.config)
        self._scheduler_running = False
        self._scheduler_thread = None
    
    def get_user_weekly_stats(self, user_id: int, days: int = 7) -> Dict:
        """
        Get weekly statistics for a user.
        
        Returns:
            Dict with scan stats, threat breakdown, risk assessment
        """
        session = self.db.Session()
        try:
            # Date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Base query for user's records in the time period
            base_query = session.query(VerificationRecord).filter(
                and_(
                    VerificationRecord.user_id == user_id,
                    VerificationRecord.created_at >= start_date,
                    VerificationRecord.created_at <= end_date
                )
            )
            
            # Total scans
            total_scans = base_query.count()
            
            # Safe vs unsafe
            safe_count = base_query.filter(VerificationRecord.is_safe == True).count()
            unsafe_count = base_query.filter(VerificationRecord.is_safe == False).count()
            
            # Risk level breakdown
            risk_breakdown = {}
            risk_levels = ['safe', 'low', 'medium', 'high', 'critical']
            for level in risk_levels:
                count = base_query.filter(VerificationRecord.risk_level == level).count()
                risk_breakdown[level] = count
            
            # Source breakdown (manual vs email)
            manual_scans = base_query.filter(VerificationRecord.source == 'manual').count()
            email_scans = base_query.filter(VerificationRecord.source == 'email').count()
            
            # Get recent threats (high/critical)
            recent_threats = base_query.filter(
                VerificationRecord.risk_level.in_(['high', 'critical'])
            ).order_by(VerificationRecord.created_at.desc()).limit(10).all()
            
            # Calculate overall risk score
            if total_scans > 0:
                # Weight threats by severity
                weighted_risk = (
                    (risk_breakdown.get('critical', 0) * 1.0) +
                    (risk_breakdown.get('high', 0) * 0.75) +
                    (risk_breakdown.get('medium', 0) * 0.5) +
                    (risk_breakdown.get('low', 0) * 0.25) +
                    (risk_breakdown.get('safe', 0) * 0.0)
                ) / total_scans
                
                # Determine overall risk level
                if weighted_risk >= 0.7:
                    overall_risk = 'critical'
                    risk_description = 'Your email security is at critical risk. Immediate action recommended.'
                elif weighted_risk >= 0.5:
                    overall_risk = 'high'
                    risk_description = 'Your security posture needs attention. Multiple threats detected.'
                elif weighted_risk >= 0.3:
                    overall_risk = 'medium'
                    risk_description = 'Some concerns detected. Stay vigilant and review flagged links.'
                elif weighted_risk >= 0.1:
                    overall_risk = 'low'
                    risk_description = 'Good security posture. Minor issues detected.'
                else:
                    overall_risk = 'safe'
                    risk_description = 'Excellent! Your email links appear safe and secure.'
            else:
                weighted_risk = 0
                overall_risk = 'unknown'
                risk_description = 'No scans recorded this week. Enable email monitoring for protection.'
            
            return {
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat(),
                    'days': days
                },
                'summary': {
                    'total_scans': total_scans,
                    'safe_count': safe_count,
                    'unsafe_count': unsafe_count,
                    'safe_percentage': (safe_count / total_scans * 100) if total_scans > 0 else 0
                },
                'risk_breakdown': risk_breakdown,
                'sources': {
                    'manual': manual_scans,
                    'email': email_scans
                },
                'overall_risk': {
                    'level': overall_risk,
                    'score': weighted_risk,
                    'description': risk_description
                },
                'recent_threats': [
                    {
                        'url': t.url[:80] + '...' if len(t.url) > 80 else t.url,
                        'risk_level': t.risk_level,
                        'risk_score': t.risk_score,
                        'source': t.source,
                        'email_from': t.email_from,
                        'detected_at': t.created_at.isoformat() if t.created_at else None
                    }
                    for t in recent_threats
                ]
            }
        finally:
            session.close()
    
    def generate_report_html(self, user: Dict, stats: Dict) -> str:
        """Generate HTML email report"""
        
        # Color scheme
        risk_colors = {
            'critical': '#ef4444',
            'high': '#f59e0b',
            'medium': '#eab308',
            'low': '#22c55e',
            'safe': '#10b981',
            'unknown': '#64748b'
        }
        
        primary_color = '#0ea5e9'
        bg_dark = '#0f172a'
        bg_card = '#1e293b'
        
        risk_level = stats['overall_risk']['level']
        risk_color = risk_colors.get(risk_level, '#64748b')
        
        # Build threats table
        threats_html = ''
        if stats['recent_threats']:
            threats_rows = ''
            for threat in stats['recent_threats']:
                level_color = risk_colors.get(threat['risk_level'], '#64748b')
                threats_rows += f'''
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #334155; color: #f1f5f9; font-size: 13px; word-break: break-all;">{threat['url']}</td>
                    <td style="padding: 12px; border-bottom: 1px solid #334155; text-align: center;">
                        <span style="background: {level_color}22; color: {level_color}; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase;">{threat['risk_level']}</span>
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 13px;">{threat['source']}</td>
                </tr>
                '''
            threats_html = f'''
            <div style="margin-top: 30px;">
                <h3 style="color: #f1f5f9; font-size: 18px; margin-bottom: 16px;">🚨 Recent Threats Detected</h3>
                <table style="width: 100%; border-collapse: collapse; background: {bg_card}; border-radius: 12px; overflow: hidden;">
                    <thead>
                        <tr style="background: #334155;">
                            <th style="padding: 14px; text-align: left; color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">URL</th>
                            <th style="padding: 14px; text-align: center; color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">Risk</th>
                            <th style="padding: 14px; text-align: left; color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em;">Source</th>
                        </tr>
                    </thead>
                    <tbody>
                        {threats_rows}
                    </tbody>
                </table>
            </div>
            '''
        
        # Risk breakdown chart (simple bar representation)
        breakdown = stats['risk_breakdown']
        total = stats['summary']['total_scans'] or 1
        breakdown_html = ''
        for level in ['critical', 'high', 'medium', 'low', 'safe']:
            count = breakdown.get(level, 0)
            pct = (count / total * 100) if total > 0 else 0
            color = risk_colors.get(level, '#64748b')
            breakdown_html += f'''
            <div style="margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <span style="color: #f1f5f9; font-size: 13px; text-transform: capitalize;">{level}</span>
                    <span style="color: #94a3b8; font-size: 13px;">{count} ({pct:.1f}%)</span>
                </div>
                <div style="background: #334155; border-radius: 4px; height: 8px; overflow: hidden;">
                    <div style="background: {color}; width: {pct}%; height: 100%; border-radius: 4px;"></div>
                </div>
            </div>
            '''
        
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; background-color: {bg_dark}; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
            <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
                
                <!-- Header -->
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: {primary_color}; font-size: 28px; margin: 0 0 8px 0;">🛡️ SecureLink</h1>
                    <p style="color: #94a3b8; font-size: 14px; margin: 0;">Weekly Security Report</p>
                </div>
                
                <!-- Greeting -->
                <div style="background: {bg_card}; border-radius: 16px; padding: 30px; margin-bottom: 24px;">
                    <h2 style="color: #f1f5f9; font-size: 20px; margin: 0 0 8px 0;">Hello, {user.get('username', 'User')}!</h2>
                    <p style="color: #94a3b8; font-size: 14px; margin: 0; line-height: 1.6;">
                        Here's your weekly security summary for {datetime.now().strftime('%B %d, %Y')}.
                    </p>
                </div>
                
                <!-- Overall Risk Status -->
                <div style="background: linear-gradient(135deg, {risk_color}22 0%, {risk_color}11 100%); border: 1px solid {risk_color}44; border-radius: 16px; padding: 30px; margin-bottom: 24px; text-align: center;">
                    <div style="font-size: 14px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 12px;">Overall Risk Level</div>
                    <div style="font-size: 36px; font-weight: 800; color: {risk_color}; text-transform: uppercase; margin-bottom: 12px;">{risk_level}</div>
                    <p style="color: #f1f5f9; font-size: 14px; margin: 0; line-height: 1.6;">{stats['overall_risk']['description']}</p>
                </div>
                
                <!-- Stats Grid -->
                <div style="display: flex; gap: 16px; margin-bottom: 24px;">
                    <div style="flex: 1; background: {bg_card}; border-radius: 12px; padding: 24px; text-align: center;">
                        <div style="font-size: 32px; font-weight: 700; color: {primary_color};">{stats['summary']['total_scans']}</div>
                        <div style="color: #94a3b8; font-size: 13px; margin-top: 4px;">Total Scans</div>
                    </div>
                    <div style="flex: 1; background: {bg_card}; border-radius: 12px; padding: 24px; text-align: center;">
                        <div style="font-size: 32px; font-weight: 700; color: #10b981;">{stats['summary']['safe_count']}</div>
                        <div style="color: #94a3b8; font-size: 13px; margin-top: 4px;">Safe Links</div>
                    </div>
                    <div style="flex: 1; background: {bg_card}; border-radius: 12px; padding: 24px; text-align: center;">
                        <div style="font-size: 32px; font-weight: 700; color: #ef4444;">{stats['summary']['unsafe_count']}</div>
                        <div style="color: #94a3b8; font-size: 13px; margin-top: 4px;">Threats</div>
                    </div>
                </div>
                
                <!-- Risk Breakdown -->
                <div style="background: {bg_card}; border-radius: 16px; padding: 30px; margin-bottom: 24px;">
                    <h3 style="color: #f1f5f9; font-size: 18px; margin: 0 0 20px 0;">📊 Risk Breakdown</h3>
                    {breakdown_html}
                </div>
                
                <!-- Scan Sources -->
                <div style="background: {bg_card}; border-radius: 16px; padding: 30px; margin-bottom: 24px;">
                    <h3 style="color: #f1f5f9; font-size: 18px; margin: 0 0 16px 0;">📧 Scan Sources</h3>
                    <div style="display: flex; gap: 20px;">
                        <div style="flex: 1;">
                            <div style="color: #94a3b8; font-size: 13px;">Email Monitoring</div>
                            <div style="color: #f1f5f9; font-size: 24px; font-weight: 600;">{stats['sources']['email']}</div>
                        </div>
                        <div style="flex: 1;">
                            <div style="color: #94a3b8; font-size: 13px;">Manual Scans</div>
                            <div style="color: #f1f5f9; font-size: 24px; font-weight: 600;">{stats['sources']['manual']}</div>
                        </div>
                    </div>
                </div>
                
                <!-- Recent Threats -->
                {threats_html}
                
                <!-- Tips Section -->
                <div style="background: linear-gradient(135deg, {primary_color}22 0%, {primary_color}11 100%); border: 1px solid {primary_color}44; border-radius: 16px; padding: 30px; margin-top: 30px;">
                    <h3 style="color: #f1f5f9; font-size: 18px; margin: 0 0 16px 0;">💡 Security Tips</h3>
                    <ul style="color: #94a3b8; font-size: 14px; margin: 0; padding-left: 20px; line-height: 1.8;">
                        <li>Never click links from unknown senders</li>
                        <li>Check URLs carefully for typos (paypa1.com vs paypal.com)</li>
                        <li>Enable email monitoring for automatic protection</li>
                        <li>Report suspicious emails to your IT department</li>
                    </ul>
                </div>
                
                <!-- Footer -->
                <div style="text-align: center; margin-top: 40px; padding-top: 30px; border-top: 1px solid #334155;">
                    <p style="color: #64748b; font-size: 12px; margin: 0 0 8px 0;">
                        This report was generated by SecureLink
                    </p>
                    <p style="color: #64748b; font-size: 12px; margin: 0;">
                        To unsubscribe from weekly reports, update your <a href="#" style="color: {primary_color};">notification preferences</a>.
                    </p>
                </div>
                
            </div>
        </body>
        </html>
        '''
        
        return html
    
    def generate_report_text(self, user: Dict, stats: Dict) -> str:
        """Generate plain text email report"""
        lines = [
            "=" * 50,
            "SECURELINK - WEEKLY SECURITY REPORT",
            "=" * 50,
            "",
            f"Hello, {user.get('username', 'User')}!",
            f"Here's your weekly security summary for {datetime.now().strftime('%B %d, %Y')}.",
            "",
            "-" * 50,
            "OVERALL RISK ASSESSMENT",
            "-" * 50,
            f"Risk Level: {stats['overall_risk']['level'].upper()}",
            f"Description: {stats['overall_risk']['description']}",
            "",
            "-" * 50,
            "SCAN SUMMARY",
            "-" * 50,
            f"Total Scans: {stats['summary']['total_scans']}",
            f"Safe Links: {stats['summary']['safe_count']}",
            f"Threats Detected: {stats['summary']['unsafe_count']}",
            f"Safe Percentage: {stats['summary']['safe_percentage']:.1f}%",
            "",
            "-" * 50,
            "RISK BREAKDOWN",
            "-" * 50,
        ]
        
        for level in ['critical', 'high', 'medium', 'low', 'safe']:
            count = stats['risk_breakdown'].get(level, 0)
            lines.append(f"  {level.capitalize()}: {count}")
        
        lines.extend([
            "",
            "-" * 50,
            "SCAN SOURCES",
            "-" * 50,
            f"Email Monitoring: {stats['sources']['email']}",
            f"Manual Scans: {stats['sources']['manual']}",
        ])
        
        if stats['recent_threats']:
            lines.extend([
                "",
                "-" * 50,
                "RECENT THREATS",
                "-" * 50,
            ])
            for threat in stats['recent_threats']:
                lines.append(f"  [{threat['risk_level'].upper()}] {threat['url']}")
                lines.append(f"    Source: {threat['source']}")
                lines.append("")
        
        lines.extend([
            "",
            "=" * 50,
            "Stay safe online!",
            "SecureLink Team",
            "=" * 50,
        ])
        
        return "\n".join(lines)
    
    def send_report(self, user: Dict, smtp_settings: Dict = None) -> bool:
        """
        Send weekly report to a user.
        
        Args:
            user: User dict with id, email, username
            smtp_settings: Optional SMTP settings (host, port, username, password)
            
        Returns:
            True if sent successfully
        """
        try:
            # Get stats
            stats = self.get_user_weekly_stats(user['id'])
            
            # Generate content
            html_content = self.generate_report_html(user, stats)
            text_content = self.generate_report_text(user, stats)
            
            # Create email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"🛡️ Your Weekly Security Report - {datetime.now().strftime('%b %d, %Y')}"
            msg['From'] = smtp_settings.get('username', self.config.EMAIL_USERNAME) if smtp_settings else self.config.EMAIL_USERNAME
            msg['To'] = user['email']
            
            # Attach parts
            text_part = MIMEText(text_content, 'plain')
            html_part = MIMEText(html_content, 'html')
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Send
            smtp_host = smtp_settings.get('host', 'smtp.gmail.com') if smtp_settings else 'smtp.gmail.com'
            smtp_port = smtp_settings.get('port', 587) if smtp_settings else 587
            smtp_user = smtp_settings.get('username', self.config.EMAIL_USERNAME) if smtp_settings else self.config.EMAIL_USERNAME
            smtp_pass = smtp_settings.get('password', self.config.EMAIL_PASSWORD) if smtp_settings else self.config.EMAIL_PASSWORD
            
            if not smtp_user or not smtp_pass:
                logger.warning(f"SMTP credentials not configured, skipping report for {user['email']}")
                return False
            
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            
            logger.info(f"Weekly report sent to {user['email']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send weekly report to {user.get('email')}: {e}")
            return False
    
    def send_all_reports(self, auth_manager) -> Dict:
        """
        Send weekly reports to all users who have opted in.
        
        Args:
            auth_manager: AuthManager instance to get users
            
        Returns:
            Dict with sent, failed, skipped counts
        """
        results = {'sent': 0, 'failed': 0, 'skipped': 0}
        
        try:
            session = auth_manager.Session()
            from auth import User
            
            # Get all users with weekly reports enabled
            users = session.query(User).filter(
                User.weekly_reports_enabled == True,
                User.is_active == True
            ).all()
            
            for user in users:
                user_dict = {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username
                }
                
                if self.send_report(user_dict):
                    results['sent'] += 1
                else:
                    results['failed'] += 1
            
            session.close()
            logger.info(f"Weekly reports batch complete: {results}")
            
        except Exception as e:
            logger.error(f"Error sending batch weekly reports: {e}")
        
        return results
    
    def start_scheduler(self, auth_manager, day: str = 'monday', hour: int = 9):
        """
        Start the weekly report scheduler.
        
        Args:
            auth_manager: AuthManager instance
            day: Day of week to send reports
            hour: Hour (24h) to send reports
        """
        if self._scheduler_running:
            logger.warning("Scheduler already running")
            return
        
        def job():
            logger.info("Running weekly report job...")
            self.send_all_reports(auth_manager)
        
        # Schedule for the specified day and time
        getattr(schedule.every(), day).at(f"{hour:02d}:00").do(job)
        
        def run_scheduler():
            self._scheduler_running = True
            logger.info(f"Weekly report scheduler started. Reports will be sent every {day} at {hour:02d}:00")
            while self._scheduler_running:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        
        self._scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        self._scheduler_thread.start()
    
    def stop_scheduler(self):
        """Stop the scheduler"""
        self._scheduler_running = False
        schedule.clear()
        logger.info("Weekly report scheduler stopped")
    
    # ==================== Hourly Threat Reports ====================
    
    def get_hourly_flagged_emails(self, user_id: int) -> List[Dict]:
        """
        Get flagged emails from the last hour for a user.
        
        Returns:
            List of flagged email records with threat details
        """
        session = self.db.Session()
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)
            
            # Get all flagged records (non-safe) from email source in the last hour
            flagged = session.query(VerificationRecord).filter(
                and_(
                    VerificationRecord.user_id == user_id,
                    VerificationRecord.source == 'email',
                    VerificationRecord.is_safe == False,
                    VerificationRecord.created_at >= start_time,
                    VerificationRecord.created_at <= end_time
                )
            ).order_by(VerificationRecord.created_at.desc()).all()
            
            return [record.to_dict() for record in flagged]
        finally:
            session.close()
    
    def generate_hourly_report_html(self, user: Dict, flagged_emails: List[Dict]) -> str:
        """Generate HTML content for hourly threat report"""
        primary_color = "#0ea5e9"
        danger_color = "#ef4444"
        warning_color = "#f59e0b"
        
        risk_colors = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#d97706',
            'low': '#0891b2'
        }
        
        # Build email rows
        email_rows = ""
        for email in flagged_emails:
            risk_color = risk_colors.get(email.get('risk_level', 'medium'), '#d97706')
            threats = email.get('threats_detected', [])
            threats_html = "<br>".join([f"• {t}" for t in threats[:3]]) if threats else "Suspicious characteristics detected"
            
            # Truncate URL for display
            url = email.get('url', 'Unknown URL')
            display_url = url[:60] + "..." if len(url) > 60 else url
            
            email_rows += f"""
            <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 16px; vertical-align: top;">
                    <div style="font-weight: 600; color: #1e293b; margin-bottom: 4px;">
                        {email.get('email_subject', 'No Subject')[:50]}
                    </div>
                    <div style="font-size: 13px; color: #64748b;">
                        From: {email.get('email_from', 'Unknown Sender')}
                    </div>
                </td>
                <td style="padding: 16px; vertical-align: top;">
                    <div style="background: {risk_color}22; color: {risk_color}; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; display: inline-block;">
                        {email.get('risk_level', 'Unknown').upper()}
                    </div>
                </td>
                <td style="padding: 16px; vertical-align: top; max-width: 250px;">
                    <div style="font-family: monospace; font-size: 12px; color: #dc2626; word-break: break-all; background: #fef2f2; padding: 8px; border-radius: 4px;">
                        {display_url}
                    </div>
                </td>
                <td style="padding: 16px; vertical-align: top; font-size: 13px; color: #475569;">
                    {threats_html}
                </td>
            </tr>
            """
        
        # Guidance section
        guidance_html = """
        <div style="background: #f0f9ff; border: 1px solid #0ea5e9; border-radius: 12px; padding: 20px; margin-top: 24px;">
            <h3 style="color: #0369a1; margin: 0 0 12px 0; font-size: 16px;">🛡️ What You Should Do</h3>
            <ul style="color: #0c4a6e; margin: 0; padding-left: 20px; line-height: 1.8;">
                <li><strong>Do NOT click</strong> any of the flagged links above</li>
                <li><strong>Delete</strong> the suspicious emails from your inbox</li>
                <li><strong>Report as phishing</strong> if your email provider supports it</li>
                <li><strong>Never enter</strong> personal information, passwords, or financial details on suspicious sites</li>
                <li><strong>Check the sender</strong> - legitimate companies won't ask for sensitive info via email</li>
                <li>If you accidentally clicked a link, <strong>change your passwords</strong> immediately</li>
            </ul>
        </div>
        """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f1f5f9; margin: 0; padding: 20px;">
            <div style="max-width: 700px; margin: 0 auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                
                <!-- Header -->
                <div style="background: linear-gradient(135deg, {danger_color} 0%, #b91c1c 100%); padding: 32px; text-align: center;">
                    <h1 style="color: white; margin: 0; font-size: 24px;">🚨 Hourly Threat Alert</h1>
                    <p style="color: rgba(255,255,255,0.9); font-size: 14px; margin: 8px 0 0 0;">
                        {len(flagged_emails)} suspicious email(s) detected in the last hour
                    </p>
                </div>
                
                <!-- Content -->
                <div style="padding: 32px;">
                    <p style="color: #475569; font-size: 15px; line-height: 1.6; margin: 0 0 24px 0;">
                        Hi {user.get('username', 'there')},<br><br>
                        SecureLink has detected <strong style="color: {danger_color};">{len(flagged_emails)} potentially dangerous link(s)</strong> in your monitored email accounts. 
                        Please review the details below and take appropriate action.
                    </p>
                    
                    <!-- Flagged Emails Table -->
                    <div style="border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden;">
                        <table style="width: 100%; border-collapse: collapse;">
                            <thead>
                                <tr style="background: #f8fafc;">
                                    <th style="padding: 14px 16px; text-align: left; font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600;">Email</th>
                                    <th style="padding: 14px 16px; text-align: left; font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600;">Risk</th>
                                    <th style="padding: 14px 16px; text-align: left; font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600;">Flagged Link</th>
                                    <th style="padding: 14px 16px; text-align: left; font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600;">Reason</th>
                                </tr>
                            </thead>
                            <tbody>
                                {email_rows}
                            </tbody>
                        </table>
                    </div>
                    
                    {guidance_html}
                    
                </div>
                
                <!-- Footer -->
                <div style="background: #f8fafc; padding: 24px; text-align: center; border-top: 1px solid #e2e8f0;">
                    <p style="color: #64748b; font-size: 13px; margin: 0;">
                        This is an automated security alert from <strong style="color: {primary_color};">SecureLink</strong>.<br>
                        Reports are sent hourly when threats are detected.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        return html
    
    def generate_hourly_report_text(self, user: Dict, flagged_emails: List[Dict]) -> str:
        """Generate plain text content for hourly threat report"""
        lines = [
            "=" * 60,
            "SECURELINK - HOURLY THREAT ALERT",
            "=" * 60,
            "",
            f"Hi {user.get('username', 'there')},",
            "",
            f"SecureLink has detected {len(flagged_emails)} potentially dangerous link(s)",
            "in your monitored email accounts in the last hour.",
            "",
            "-" * 60,
            "FLAGGED EMAILS:",
            "-" * 60,
        ]
        
        for i, email in enumerate(flagged_emails, 1):
            lines.extend([
                "",
                f"[{i}] {email.get('email_subject', 'No Subject')}",
                f"    From: {email.get('email_from', 'Unknown')}",
                f"    Risk Level: {email.get('risk_level', 'Unknown').upper()}",
                f"    Flagged Link: {email.get('url', 'Unknown')}",
            ])
            if email.get('threats_detected'):
                lines.append("    Threats:")
                for threat in email['threats_detected'][:3]:
                    lines.append(f"      - {threat}")
        
        lines.extend([
            "",
            "-" * 60,
            "WHAT YOU SHOULD DO:",
            "-" * 60,
            "",
            "• Do NOT click any of the flagged links",
            "• Delete the suspicious emails from your inbox",
            "• Report as phishing if your email provider supports it",
            "• Never enter personal info on suspicious sites",
            "• If you clicked a link, change your passwords immediately",
            "",
            "=" * 60,
            "This is an automated alert from SecureLink.",
            "=" * 60,
        ])
        
        return "\n".join(lines)
    
    def send_hourly_report(self, user: Dict, smtp_settings: Dict = None) -> bool:
        """
        Send hourly threat report to a user if they have flagged emails.
        
        Args:
            user: User dict with id, email, username
            smtp_settings: Optional SMTP settings
            
        Returns:
            True if sent successfully (or no threats to report)
        """
        try:
            # Get flagged emails from the last hour
            flagged_emails = self.get_hourly_flagged_emails(user['id'])
            
            # Skip if no flagged emails
            if not flagged_emails:
                logger.debug(f"No flagged emails for user {user['id']} in the last hour")
                return True
            
            # Generate report content
            html_content = self.generate_hourly_report_html(user, flagged_emails)
            text_content = self.generate_hourly_report_text(user, flagged_emails)
            
            # Create email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"🚨 SecureLink Alert: {len(flagged_emails)} Threat(s) Detected - {datetime.now().strftime('%I:%M %p')}"
            msg['From'] = smtp_settings.get('username', self.config.SMTP_USERNAME) if smtp_settings else getattr(self.config, 'SMTP_USERNAME', self.config.EMAIL_USERNAME)
            msg['To'] = user['email']
            
            # Attach parts
            text_part = MIMEText(text_content, 'plain')
            html_part = MIMEText(html_content, 'html')
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Send
            smtp_host = smtp_settings.get('host', 'smtp.gmail.com') if smtp_settings else getattr(self.config, 'SMTP_HOST', 'smtp.gmail.com')
            smtp_port = smtp_settings.get('port', 587) if smtp_settings else getattr(self.config, 'SMTP_PORT', 587)
            smtp_user = smtp_settings.get('username') if smtp_settings else getattr(self.config, 'SMTP_USERNAME', self.config.EMAIL_USERNAME)
            smtp_pass = smtp_settings.get('password') if smtp_settings else getattr(self.config, 'SMTP_PASSWORD', self.config.EMAIL_PASSWORD)
            
            if not smtp_user or not smtp_pass:
                logger.warning(f"SMTP credentials not configured, skipping hourly report for {user['email']}")
                return False
            
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            
            logger.info(f"Hourly threat report sent to {user['email']} with {len(flagged_emails)} flagged emails")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send hourly report to {user.get('email')}: {e}")
            return False
    
    def send_all_hourly_reports(self, auth_manager) -> Dict:
        """
        Send hourly threat reports to all users with active email monitoring.
        
        Args:
            auth_manager: AuthManager instance to get users
            
        Returns:
            Dict with sent, skipped counts
        """
        results = {'sent': 0, 'skipped': 0, 'failed': 0}
        
        try:
            session = auth_manager.Session()
            from auth import User, EmailAccount
            
            # Get all users with active email monitoring
            users_with_monitoring = session.query(User).join(
                EmailAccount, User.id == EmailAccount.user_id
            ).filter(
                EmailAccount.is_active == True,
                EmailAccount.is_verified == True,
                User.is_active == True
            ).distinct().all()
            
            for user in users_with_monitoring:
                user_dict = {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username
                }
                
                # Check if user has flagged emails in the last hour
                flagged = self.get_hourly_flagged_emails(user.id)
                if flagged:
                    if self.send_hourly_report(user_dict):
                        results['sent'] += 1
                    else:
                        results['failed'] += 1
                else:
                    results['skipped'] += 1
            
            session.close()
            logger.info(f"Hourly reports batch complete: {results}")
            
        except Exception as e:
            logger.error(f"Error sending batch hourly reports: {e}")
        
        return results
    
    def start_hourly_scheduler(self, auth_manager):
        """
        Start the hourly threat report scheduler.
        
        Args:
            auth_manager: AuthManager instance
        """
        def hourly_job():
            logger.info("Running hourly threat report job...")
            self.send_all_hourly_reports(auth_manager)
        
        # Schedule to run every hour
        schedule.every().hour.do(hourly_job)
        
        logger.info("Hourly threat report scheduler enabled - reports will be sent every hour when threats are detected")


# Global instance
_report_generator = None

def get_report_generator() -> WeeklyReportGenerator:
    """Get or create the report generator singleton"""
    global _report_generator
    if _report_generator is None:
        _report_generator = WeeklyReportGenerator()
    return _report_generator
