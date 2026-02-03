"""
Notification Service - Handles desktop and email notifications for link verification results.

Copyright (c) 2026 Ryan Haley. All Rights Reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import threading

from config import Config
from link_verifier import VerificationResult, RiskLevel

logger = logging.getLogger(__name__)

# Try to import notification libraries
try:
    from plyer import notification as plyer_notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

try:
    from win10toast import ToastNotifier
    WIN10TOAST_AVAILABLE = True
except ImportError:
    WIN10TOAST_AVAILABLE = False


class NotificationService:
    """
    Service for sending notifications about link verification results.
    Supports desktop notifications (Windows/Mac/Linux) and email notifications.
    """
    
    def __init__(self, config: Config = None):
        """Initialize the notification service"""
        self.config = config or Config()
        self._toast = None
        
        if WIN10TOAST_AVAILABLE:
            try:
                self._toast = ToastNotifier()
            except:
                pass
    
    def notify(self, result: VerificationResult, email_context: str = None):
        """
        Send notification based on verification result.
        
        Args:
            result: The verification result
            email_context: Optional context about the email the link was found in
        """
        # Only notify for medium risk and above
        if result.risk_level in [RiskLevel.SAFE, RiskLevel.LOW]:
            return
        
        title = self._get_notification_title(result)
        message = self._get_notification_message(result, email_context)
        
        # Send desktop notification
        if self.config.ENABLE_DESKTOP_NOTIFICATIONS:
            self._send_desktop_notification(title, message, result.risk_level)
        
        # Send email notification
        if self.config.ENABLE_EMAIL_NOTIFICATIONS and self.config.NOTIFICATION_EMAIL:
            self._send_email_notification(title, message, result)
    
    def _get_notification_title(self, result: VerificationResult) -> str:
        """Generate notification title based on risk level"""
        icons = {
            RiskLevel.CRITICAL: "🚨",
            RiskLevel.HIGH: "⚠️",
            RiskLevel.MEDIUM: "⚡",
            RiskLevel.LOW: "ℹ️",
            RiskLevel.SAFE: "✅"
        }
        icon = icons.get(result.risk_level, "")
        return f"{icon} Link Security Alert - {result.risk_level.value.upper()}"
    
    def _get_notification_message(self, result: VerificationResult, email_context: str = None) -> str:
        """Generate notification message"""
        lines = []
        
        # Truncate URL for display
        url_display = result.url[:50] + "..." if len(result.url) > 50 else result.url
        lines.append(f"URL: {url_display}")
        lines.append(f"Risk Score: {result.risk_score:.0%}")
        
        if email_context:
            lines.append(f"Found in: {email_context}")
        
        if result.threats_detected:
            lines.append(f"Threats: {', '.join(result.threats_detected[:2])}")
        
        return "\n".join(lines)
    
    def _send_desktop_notification(self, title: str, message: str, risk_level: RiskLevel):
        """Send desktop notification"""
        try:
            # Determine urgency/timeout based on risk
            timeout = 10 if risk_level == RiskLevel.CRITICAL else 5
            
            # Try win10toast first on Windows
            if WIN10TOAST_AVAILABLE and self._toast:
                threading.Thread(
                    target=self._toast.show_toast,
                    kwargs={
                        'title': title,
                        'msg': message,
                        'duration': timeout,
                        'threaded': False
                    },
                    daemon=True
                ).start()
                logger.info("Desktop notification sent via win10toast")
                return
            
            # Fall back to plyer
            if PLYER_AVAILABLE:
                plyer_notification.notify(
                    title=title,
                    message=message,
                    timeout=timeout,
                    app_name="SecureLink"
                )
                logger.info("Desktop notification sent via plyer")
                return
            
            logger.warning("No notification library available")
            
        except Exception as e:
            logger.error(f"Failed to send desktop notification: {e}")
    
    def _send_email_notification(self, title: str, message: str, result: VerificationResult):
        """Send email notification"""
        try:
            # Create email content
            html_content = self._generate_email_html(result)
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = title
            msg['From'] = self.config.EMAIL_USERNAME
            msg['To'] = self.config.NOTIFICATION_EMAIL
            
            # Plain text version
            text_part = MIMEText(message, 'plain')
            msg.attach(text_part)
            
            # HTML version
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Send via SMTP
            # Note: This uses the same credentials as IMAP
            # For production, you might want separate SMTP settings
            smtp_host = self.config.EMAIL_HOST.replace('imap.', 'smtp.')
            smtp_port = 587
            
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(self.config.EMAIL_USERNAME, self.config.EMAIL_PASSWORD)
                server.send_message(msg)
            
            logger.info(f"Email notification sent to {self.config.NOTIFICATION_EMAIL}")
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
    
    def _generate_email_html(self, result: VerificationResult) -> str:
        """Generate HTML email content"""
        risk_colors = {
            RiskLevel.CRITICAL: "#dc3545",
            RiskLevel.HIGH: "#fd7e14",
            RiskLevel.MEDIUM: "#ffc107",
            RiskLevel.LOW: "#17a2b8",
            RiskLevel.SAFE: "#28a745"
        }
        
        color = risk_colors.get(result.risk_level, "#6c757d")
        
        threats_html = ""
        if result.threats_detected:
            threats_html = "<h3>Threats Detected:</h3><ul>"
            for threat in result.threats_detected:
                threats_html += f"<li style='color: #dc3545;'>{threat}</li>"
            threats_html += "</ul>"
        
        warnings_html = ""
        if result.warnings:
            warnings_html = "<h3>Warnings:</h3><ul>"
            for warning in result.warnings:
                warnings_html += f"<li style='color: #fd7e14;'>{warning}</li>"
            warnings_html += "</ul>"
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; }}
                .header {{ background-color: {color}; color: white; padding: 15px; border-radius: 5px; }}
                .content {{ padding: 20px; background-color: #f8f9fa; margin-top: 10px; border-radius: 5px; }}
                .url {{ word-break: break-all; background-color: #e9ecef; padding: 10px; border-radius: 3px; }}
                .score {{ font-size: 24px; font-weight: bold; color: {color}; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🔒 Link Security Alert</h2>
                <p>Risk Level: <strong>{result.risk_level.value.upper()}</strong></p>
            </div>
            <div class="content">
                <h3>URL Analyzed:</h3>
                <div class="url">{result.url}</div>
                
                <h3>Risk Score:</h3>
                <p class="score">{result.risk_score:.0%}</p>
                
                {threats_html}
                {warnings_html}
                
                <hr>
                <p style="color: #6c757d; font-size: 12px;">
                    This alert was generated by SecureLink at {result.verified_at.strftime('%Y-%m-%d %H:%M:%S')}
                </p>
            </div>
        </body>
        </html>
        """


def send_notification(result: VerificationResult, email_context: str = None):
    """Convenience function to send a notification"""
    service = NotificationService()
    service.notify(result, email_context)


if __name__ == "__main__":
    # Test notification
    from link_verifier import verify_link
    
    result = verify_link("http://suspicious-paypa1.tk/login")
    service = NotificationService()
    service.notify(result, "Test Email Subject")
