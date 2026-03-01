"""
Notification Service - Handles desktop and email notifications for link verification results.

Copyright (c) 2026 SecureLink. All rights reserved.
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
            msg['From'] = getattr(self.config, 'SMTP_FROM_EMAIL', None) or getattr(self.config, 'SMTP_USERNAME', None) or 'support@securelinkapp.com'
            msg['To'] = self.config.NOTIFICATION_EMAIL
            
            # Plain text version
            text_part = MIMEText(message, 'plain')
            msg.attach(text_part)
            
            # HTML version
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Send via SMTP
            smtp_host = getattr(self.config, 'SMTP_HOST', None) or 'email-smtp.us-east-2.amazonaws.com'
            smtp_port = getattr(self.config, 'SMTP_PORT', None) or 587
            smtp_user = getattr(self.config, 'SMTP_USERNAME', None) or self.config.EMAIL_USERNAME
            smtp_pass = getattr(self.config, 'SMTP_PASSWORD', None) or self.config.EMAIL_PASSWORD
            
            if getattr(self.config, 'SMTP_USE_SSL', False) or smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
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


def send_ticket_notification(ticket_data: dict, config: Config = None):
    """
    Send email notification when a new support ticket is created.
    
    Args:
        ticket_data: Dictionary containing ticket information
        config: Optional Config object
    """
    config = config or Config()
    
    if not config.SUPPORT_EMAIL:
        logger.warning("SUPPORT_EMAIL not configured - ticket notification not sent")
        return False
    
    if not config.SMTP_USERNAME or not config.SMTP_PASSWORD:
        logger.warning("SMTP credentials not configured - ticket notification not sent")
        return False
    
    try:
        subject = f"🎫 New Support Ticket: {ticket_data.get('ticket_number', 'N/A')} - {ticket_data.get('subject', 'No Subject')}"
        
        priority = ticket_data.get('priority', 'medium').upper()
        priority_colors = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107', 
            'HIGH': '#fd7e14',
            'URGENT': '#dc3545'
        }
        priority_color = priority_colors.get(priority, '#6c757d')
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; }}
                .content {{ padding: 25px; }}
                .field {{ margin-bottom: 15px; }}
                .label {{ font-weight: bold; color: #555; font-size: 12px; text-transform: uppercase; }}
                .value {{ margin-top: 5px; color: #333; }}
                .priority {{ display: inline-block; padding: 5px 12px; border-radius: 20px; color: white; font-weight: bold; font-size: 12px; }}
                .description {{ background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #667eea; }}
                .footer {{ background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #888; }}
                .btn {{ display: inline-block; background: #667eea; color: white; padding: 10px 25px; text-decoration: none; border-radius: 5px; margin-top: 15px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2 style="margin: 0;">🎫 New Support Ticket</h2>
                    <p style="margin: 10px 0 0 0; opacity: 0.9;">Ticket #{ticket_data.get('ticket_number', 'N/A')}</p>
                </div>
                <div class="content">
                    <div class="field">
                        <div class="label">Priority</div>
                        <div class="value">
                            <span class="priority" style="background-color: {priority_color};">{priority}</span>
                        </div>
                    </div>
                    
                    <div class="field">
                        <div class="label">Category</div>
                        <div class="value">{ticket_data.get('category', 'General')}</div>
                    </div>
                    
                    <div class="field">
                        <div class="label">From</div>
                        <div class="value">{ticket_data.get('customer_name', 'Unknown')} ({ticket_data.get('customer_email', 'No email')})</div>
                    </div>
                    
                    <div class="field">
                        <div class="label">Subject</div>
                        <div class="value" style="font-size: 18px; font-weight: bold;">{ticket_data.get('subject', 'No Subject')}</div>
                    </div>
                    
                    <div class="field">
                        <div class="label">Description</div>
                        <div class="description">{ticket_data.get('description', 'No description provided.')}</div>
                    </div>
                    
                    <a href="{config.APP_URL}/admin/tickets" class="btn">View in Admin Panel</a>
                </div>
                <div class="footer">
                    SecureLink Support System | {ticket_data.get('created_at', 'Just now')}
                </div>
            </div>
        </body>
        </html>
        """
        
        plain_text = f"""
        New Support Ticket #{ticket_data.get('ticket_number', 'N/A')}
        
        Priority: {priority}
        Category: {ticket_data.get('category', 'General')}
        From: {ticket_data.get('customer_name', 'Unknown')} ({ticket_data.get('customer_email', 'No email')})
        Subject: {ticket_data.get('subject', 'No Subject')}
        
        Description:
        {ticket_data.get('description', 'No description provided.')}
        
        View ticket: {config.APP_URL}/admin/tickets
        """
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = config.SMTP_FROM_EMAIL
        msg['To'] = config.SUPPORT_EMAIL
        
        msg.attach(MIMEText(plain_text, 'plain'))
        msg.attach(MIMEText(html_content, 'html'))
        
        # Use SSL for port 465 (GoDaddy, etc.) or TLS for port 587 (Gmail, etc.)
        if config.SMTP_USE_SSL or config.SMTP_PORT == 465:
            with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT) as server:
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
                if config.SMTP_USE_TLS:
                    server.starttls()
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                server.send_message(msg)
        
        logger.info(f"Ticket notification sent to {config.SUPPORT_EMAIL}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send ticket notification: {e}")
        return False


def send_ticket_closure_notification(ticket_data: dict, config: Config = None):
    """
    Send email notification to customer when their ticket is closed/resolved.
    
    Args:
        ticket_data: Dictionary containing ticket information
        config: Optional Config object
    """
    config = config or Config()
    
    print(f"[CLOSURE EMAIL] Starting notification for ticket {ticket_data.get('ticket_number')}")
    
    customer_email = ticket_data.get('customer_email')
    if not customer_email:
        print("[CLOSURE EMAIL] FAILED: No customer email")
        logger.warning("No customer email - ticket closure notification not sent")
        return False
    
    if not config.SMTP_USERNAME or not config.SMTP_PASSWORD:
        print(f"[CLOSURE EMAIL] FAILED: SMTP not configured (user: {config.SMTP_USERNAME})")
        logger.warning("SMTP credentials not configured - ticket closure notification not sent")
        return False
    
    print(f"[CLOSURE EMAIL] Sending to: {customer_email} via {config.SMTP_HOST}:{config.SMTP_PORT}")
    
    try:
        ticket_number = ticket_data.get('ticket_number', 'N/A')
        subject_text = ticket_data.get('subject', 'Your Support Request')
        status = ticket_data.get('status', 'resolved').replace('_', ' ').title()
        resolution_notes = ticket_data.get('resolution_notes', '')
        
        email_subject = f"✅ Your Support Ticket {ticket_number} Has Been {status}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 25px; }}
                .ticket-info {{ background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px; }}
                .ticket-number {{ font-family: monospace; font-size: 1.1rem; color: #10b981; }}
                .resolution {{ background: #ecfdf5; padding: 15px; border-radius: 8px; border-left: 4px solid #10b981; margin-top: 15px; }}
                .footer {{ background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #888; }}
                .btn {{ display: inline-block; background: #10b981; color: white; padding: 10px 25px; text-decoration: none; border-radius: 5px; margin-top: 15px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2 style="margin: 0;">✅ Ticket {status}</h2>
                    <p style="margin: 10px 0 0 0; opacity: 0.9;">Your support request has been addressed</p>
                </div>
                <div class="content">
                    <p>Hello {ticket_data.get('customer_name', 'Valued Customer')},</p>
                    
                    <p>We wanted to let you know that your support ticket has been {status.lower()}.</p>
                    
                    <div class="ticket-info">
                        <strong>Ticket Number:</strong> <span class="ticket-number">{ticket_number}</span><br>
                        <strong>Subject:</strong> {subject_text}<br>
                        <strong>Status:</strong> {status}
                    </div>
                    
                    {"<div class='resolution'><strong>Resolution Notes:</strong><br>" + resolution_notes + "</div>" if resolution_notes else ""}
                    
                    <p>If you have any further questions or if the issue persists, please don't hesitate to open a new ticket or reply to this email.</p>
                    
                    <p>Thank you for using SecureLink!</p>
                    
                    <a href="{config.APP_URL}" class="btn">Visit SecureLink</a>
                </div>
                <div class="footer">
                    SecureLink Support Team | This is an automated message
                </div>
            </div>
        </body>
        </html>
        """
        
        plain_text = f"""
        Ticket {status}
        
        Hello {ticket_data.get('customer_name', 'Valued Customer')},
        
        Your support ticket has been {status.lower()}.
        
        Ticket Number: {ticket_number}
        Subject: {subject_text}
        Status: {status}
        
        {"Resolution Notes: " + resolution_notes if resolution_notes else ""}
        
        If you have any further questions, please open a new ticket.
        
        Thank you for using SecureLink!
        
        Visit: {config.APP_URL}
        """
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = email_subject
        msg['From'] = config.SMTP_FROM_EMAIL
        msg['To'] = customer_email
        
        msg.attach(MIMEText(plain_text, 'plain'))
        msg.attach(MIMEText(html_content, 'html'))
        
        if config.SMTP_USE_SSL or config.SMTP_PORT == 465:
            with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT) as server:
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
                if config.SMTP_USE_TLS:
                    server.starttls()
                server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                server.send_message(msg)
        
        logger.info(f"Ticket closure notification sent to {customer_email}")
        print(f"[CLOSURE EMAIL] SUCCESS: Email sent to {customer_email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send ticket closure notification: {e}")
        print(f"[CLOSURE EMAIL] ERROR: {e}")
        return False


if __name__ == "__main__":
    # Test notification
    from link_verifier import verify_link
    
    result = verify_link("http://suspicious-paypa1.tk/login")
    service = NotificationService()
    service.notify(result, "Test Email Subject")
