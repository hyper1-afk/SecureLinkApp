"""
Email Monitor - Module for monitoring email inbox and extracting links for verification.

Copyright (c) 2026 SecureLink. All rights reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""
import re
import email
import logging
import threading
import time
import smtplib
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser

from imapclient import IMAPClient

from config import Config
from link_verifier import LinkVerifier, VerificationResult, RiskLevel

logger = logging.getLogger(__name__)


@dataclass
class EmailLink:
    """Represents a link found in an email"""
    url: str
    email_subject: str
    email_from: str
    email_date: datetime
    email_uid: int
    context: str = ""  # Text around the link
    
    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'email_subject': self.email_subject,
            'email_from': self.email_from,
            'email_date': self.email_date.isoformat() if self.email_date else None,
            'email_uid': self.email_uid,
            'context': self.context
        }


class HTMLLinkExtractor(HTMLParser):
    """HTML Parser to extract links from email body"""
    
    def __init__(self):
        super().__init__()
        self.links = []
        self.current_text = ""
        
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for attr, value in attrs:
                if attr == 'href' and value:
                    if value.startswith(('http://', 'https://', 'www.')):
                        self.links.append(value)
    
    def handle_data(self, data):
        self.current_text += data
    
    def get_links(self) -> List[str]:
        return list(set(self.links))


class EmailMonitor:
    """
    Email monitoring service that connects to an IMAP server,
    monitors incoming emails, and extracts links for verification.
    """
    
    # Common URL pattern
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+|'
        r'www\.[^\s<>"{}|\\^`\[\]]+'
    )
    
    def __init__(self, config: Config = None, on_link_found: Callable = None):
        """
        Initialize the email monitor.
        
        Args:
            config: Application configuration
            on_link_found: Callback function when a link is found and verified
        """
        self.config = config or Config()
        self.on_link_found = on_link_found
        self.verifier = LinkVerifier(config)
        self.client: Optional[IMAPClient] = None
        self.running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._processed_uids = set()
    
    def connect(self) -> bool:
        """Connect to the IMAP server"""
        try:
            self.client = IMAPClient(
                self.config.EMAIL_HOST,
                port=self.config.EMAIL_PORT,
                ssl=self.config.EMAIL_USE_SSL
            )
            self.client.login(
                self.config.EMAIL_USERNAME,
                self.config.EMAIL_PASSWORD
            )
            logger.info(f"Connected to {self.config.EMAIL_HOST}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to email server: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the IMAP server"""
        if self.client:
            try:
                self.client.logout()
            except:
                pass
            self.client = None
        logger.info("Disconnected from email server")
    
    def quarantine_email(self, uid: int, folder: str = "INBOX") -> bool:
        """
        Move an email to quarantine folder.
        Creates the quarantine folder if it doesn't exist.
        
        Args:
            uid: The email UID to quarantine
            folder: The folder the email is currently in
            
        Returns:
            True if successfully quarantined, False otherwise
        """
        try:
            if not self.client:
                if not self.connect():
                    return False
            
            quarantine_folder = "SecureLink-Quarantine"
            
            # Check if quarantine folder exists, create if not
            folders = self.client.list_folders()
            folder_names = [f[2] for f in folders]
            
            if quarantine_folder not in folder_names:
                try:
                    self.client.create_folder(quarantine_folder)
                    logger.info(f"Created quarantine folder: {quarantine_folder}")
                except Exception as e:
                    logger.error(f"Failed to create quarantine folder: {e}")
                    # Try alternative folder name
                    quarantine_folder = "INBOX.SecureLink-Quarantine"
                    if quarantine_folder not in folder_names:
                        try:
                            self.client.create_folder(quarantine_folder)
                        except:
                            quarantine_folder = "Junk"  # Fall back to Junk/Spam
            
            # Select the source folder
            self.client.select_folder(folder)
            
            # Copy email to quarantine folder
            self.client.copy([uid], quarantine_folder)
            
            # Mark original as deleted and expunge
            self.client.delete_messages([uid])
            self.client.expunge()
            
            logger.info(f"Email {uid} quarantined to {quarantine_folder}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to quarantine email {uid}: {e}")
            return False
    
    def send_threat_report(self, email_link: 'EmailLink', result: VerificationResult, 
                          recipient_email: str = None) -> bool:
        """
        Send a detailed threat report email about a high-risk link.
        
        Args:
            email_link: The EmailLink object containing email details
            result: The verification result
            recipient_email: Email address to send report to (defaults to user's email)
            
        Returns:
            True if report sent successfully, False otherwise
        """
        try:
            recipient = recipient_email or self.config.EMAIL_USERNAME
            
            # Generate the threat report HTML
            html_content = self._generate_threat_report_html(email_link, result)
            text_content = self._generate_threat_report_text(email_link, result)
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"🚨 SECURITY ALERT: High-Risk Link Detected - {result.risk_level.value.upper()}"
            msg['From'] = getattr(self.config, 'SMTP_FROM_EMAIL', None) or getattr(self.config, 'SMTP_USERNAME', None) or 'support@securelinkapp.com'
            msg['To'] = recipient
            
            # Add plain text version
            text_part = MIMEText(text_content, 'plain')
            msg.attach(text_part)
            
            # Add HTML version
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # SMTP settings
            smtp_host = getattr(self.config, 'SMTP_HOST', None) or 'email-smtp.us-east-2.amazonaws.com'
            smtp_port = getattr(self.config, 'SMTP_PORT', None) or 587
            smtp_user = getattr(self.config, 'SMTP_USERNAME', None) or self.config.EMAIL_USERNAME
            smtp_pass = getattr(self.config, 'SMTP_PASSWORD', None) or self.config.EMAIL_PASSWORD
            
            # Send the email
            if getattr(self.config, 'SMTP_USE_SSL', False) or smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            
            logger.info(f"Threat report sent to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send threat report: {e}")
            return False
    
    def _generate_threat_report_html(self, email_link: 'EmailLink', result: VerificationResult) -> str:
        """Generate detailed HTML threat report"""
        risk_colors = {
            RiskLevel.CRITICAL: "#dc2626",
            RiskLevel.HIGH: "#ea580c",
            RiskLevel.MEDIUM: "#d97706",
            RiskLevel.LOW: "#0891b2",
            RiskLevel.SAFE: "#16a34a"
        }
        
        risk_color = risk_colors.get(result.risk_level, "#6b7280")
        
        # Build threats list
        threats_html = ""
        if result.threats_detected:
            threats_html = """
            <div style="background: #fef2f2; border-left: 4px solid #dc2626; padding: 16px; border-radius: 0 8px 8px 0; margin: 16px 0;">
                <h3 style="color: #991b1b; margin: 0 0 12px 0; font-size: 16px;">⚠️ Threats Detected</h3>
                <ul style="margin: 0; padding-left: 20px; color: #7f1d1d;">
            """
            for threat in result.threats_detected:
                threats_html += f"<li style='margin-bottom: 8px;'>{threat}</li>"
            threats_html += "</ul></div>"
        
        # Build warnings list
        warnings_html = ""
        if result.warnings:
            warnings_html = """
            <div style="background: #fffbeb; border-left: 4px solid #d97706; padding: 16px; border-radius: 0 8px 8px 0; margin: 16px 0;">
                <h3 style="color: #92400e; margin: 0 0 12px 0; font-size: 16px;">⚡ Warnings</h3>
                <ul style="margin: 0; padding-left: 20px; color: #78350f;">
            """
            for warning in result.warnings:
                warnings_html += f"<li style='margin-bottom: 8px;'>{warning}</li>"
            warnings_html += "</ul></div>"
        
        # Build analysis details
        analysis_html = ""
        if result.analysis_details:
            analysis_html = """
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; padding: 16px; border-radius: 8px; margin: 16px 0;">
                <h3 style="color: #475569; margin: 0 0 12px 0; font-size: 16px;">📊 Analysis Details</h3>
                <div style="color: #64748b; font-size: 14px;">
            """
            for key, value in result.analysis_details.items():
                if value and key not in ['raw_response']:
                    formatted_key = key.replace('_', ' ').title()
                    analysis_html += f"<p style='margin: 8px 0;'><strong>{formatted_key}:</strong> {value}</p>"
            analysis_html += "</div></div>"
        
        quarantine_notice = ""
        if result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            quarantine_notice = """
            <div style="background: #f0fdf4; border-left: 4px solid #16a34a; padding: 16px; border-radius: 0 8px 8px 0; margin: 16px 0;">
                <h3 style="color: #166534; margin: 0 0 8px 0; font-size: 16px;">✅ Automatic Action Taken</h3>
                <p style="color: #15803d; margin: 0; font-size: 14px;">
                    This email has been automatically moved to the <strong>SecureLink-Quarantine</strong> folder for your safety.
                    Review it carefully before taking any action.
                </p>
            </div>
            """
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f1f5f9; margin: 0; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                
                <!-- Header -->
                <div style="background: linear-gradient(135deg, {risk_color} 0%, #1e293b 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0 0 8px 0; font-size: 24px;">🚨 Security Alert</h1>
                    <p style="color: rgba(255,255,255,0.9); margin: 0; font-size: 16px;">High-Risk Link Detected in Your Email</p>
                </div>
                
                <!-- Risk Badge -->
                <div style="text-align: center; margin-top: -20px;">
                    <span style="display: inline-block; background: {risk_color}; color: white; padding: 8px 24px; border-radius: 20px; font-weight: bold; font-size: 14px; box-shadow: 0 2px 4px rgba(0,0,0,0.2);">
                        RISK LEVEL: {result.risk_level.value.upper()}
                    </span>
                </div>
                
                <!-- Content -->
                <div style="padding: 30px;">
                    
                    <!-- Risk Score -->
                    <div style="text-align: center; margin: 20px 0;">
                        <div style="font-size: 48px; font-weight: bold; color: {risk_color};">{result.risk_score:.0%}</div>
                        <div style="color: #64748b; font-size: 14px;">Risk Score</div>
                    </div>
                    
                    <!-- Email Details -->
                    <div style="background: #f8fafc; border-radius: 12px; padding: 20px; margin: 20px 0;">
                        <h3 style="color: #334155; margin: 0 0 16px 0; font-size: 16px;">📧 Original Email Details</h3>
                        <table style="width: 100%; font-size: 14px; color: #475569;">
                            <tr>
                                <td style="padding: 8px 0; font-weight: 600; width: 100px;">From:</td>
                                <td style="padding: 8px 0; word-break: break-all;">{email_link.email_from}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; font-weight: 600;">Subject:</td>
                                <td style="padding: 8px 0;">{email_link.email_subject}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px 0; font-weight: 600;">Date:</td>
                                <td style="padding: 8px 0;">{email_link.email_date.strftime('%B %d, %Y at %I:%M %p') if email_link.email_date else 'Unknown'}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <!-- Malicious URL -->
                    <div style="background: #fef2f2; border: 2px solid #fecaca; border-radius: 12px; padding: 20px; margin: 20px 0;">
                        <h3 style="color: #991b1b; margin: 0 0 12px 0; font-size: 16px;">🔗 Suspicious Link</h3>
                        <div style="background: white; padding: 12px; border-radius: 8px; word-break: break-all; font-family: monospace; font-size: 13px; color: #dc2626; border: 1px solid #fecaca;">
                            {result.url}
                        </div>
                        <p style="color: #b91c1c; font-size: 12px; margin: 12px 0 0 0;">
                            ⚠️ <strong>DO NOT CLICK THIS LINK!</strong> It has been identified as potentially dangerous.
                        </p>
                    </div>
                    
                    {threats_html}
                    {warnings_html}
                    {analysis_html}
                    {quarantine_notice}
                    
                    <!-- Recommendations -->
                    <div style="background: #eff6ff; border-left: 4px solid #3b82f6; padding: 16px; border-radius: 0 8px 8px 0; margin: 20px 0;">
                        <h3 style="color: #1e40af; margin: 0 0 12px 0; font-size: 16px;">💡 Recommendations</h3>
                        <ul style="margin: 0; padding-left: 20px; color: #1e3a8a; font-size: 14px;">
                            <li style="margin-bottom: 8px;">Do not click on the suspicious link</li>
                            <li style="margin-bottom: 8px;">Do not reply to or forward this email</li>
                            <li style="margin-bottom: 8px;">If you know the sender, contact them through a different channel to verify</li>
                            <li style="margin-bottom: 8px;">Report this email as phishing/spam to your email provider</li>
                            <li style="margin-bottom: 8px;">Delete the email permanently from your quarantine folder</li>
                        </ul>
                    </div>
                    
                </div>
                
                <!-- Footer -->
                <div style="background: #1e293b; padding: 20px; text-align: center;">
                    <p style="color: #94a3b8; margin: 0 0 8px 0; font-size: 14px;">
                        🔒 Protected by <strong style="color: #0ea5e9;">SecureLink</strong>
                    </p>
                    <p style="color: #64748b; margin: 0; font-size: 12px;">
                        Report generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
                    </p>
                </div>
                
            </div>
        </body>
        </html>
        """
    
    def _generate_threat_report_text(self, email_link: 'EmailLink', result: VerificationResult) -> str:
        """Generate plain text threat report"""
        lines = [
            "=" * 60,
            "🚨 SECURELINK SECURITY ALERT",
            "=" * 60,
            "",
            f"RISK LEVEL: {result.risk_level.value.upper()}",
            f"RISK SCORE: {result.risk_score:.0%}",
            "",
            "-" * 60,
            "ORIGINAL EMAIL DETAILS",
            "-" * 60,
            f"From: {email_link.email_from}",
            f"Subject: {email_link.email_subject}",
            f"Date: {email_link.email_date.strftime('%Y-%m-%d %H:%M') if email_link.email_date else 'Unknown'}",
            "",
            "-" * 60,
            "SUSPICIOUS LINK",
            "-" * 60,
            result.url,
            "",
            "⚠️ DO NOT CLICK THIS LINK!",
            ""
        ]
        
        if result.threats_detected:
            lines.extend([
                "-" * 60,
                "THREATS DETECTED",
                "-" * 60
            ])
            for threat in result.threats_detected:
                lines.append(f"  • {threat}")
            lines.append("")
        
        if result.warnings:
            lines.extend([
                "-" * 60,
                "WARNINGS",
                "-" * 60
            ])
            for warning in result.warnings:
                lines.append(f"  • {warning}")
            lines.append("")
        
        if result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            lines.extend([
                "-" * 60,
                "AUTOMATIC ACTION TAKEN",
                "-" * 60,
                "This email has been moved to the SecureLink-Quarantine folder.",
                ""
            ])
        
        lines.extend([
            "-" * 60,
            "RECOMMENDATIONS",
            "-" * 60,
            "  • Do not click on the suspicious link",
            "  • Do not reply to or forward this email",
            "  • Contact the sender through a different channel to verify",
            "  • Report this email as phishing/spam",
            "  • Delete the email permanently",
            "",
            "=" * 60,
            f"Report generated by SecureLink on {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "=" * 60
        ])
        
        return "\n".join(lines)
    
    def start_monitoring(self, folder: str = "INBOX"):
        """Start monitoring emails in a background thread"""
        if self.running:
            logger.warning("Monitor is already running")
            return
        
        self.running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(folder,),
            daemon=True
        )
        self._monitor_thread.start()
        logger.info(f"Started monitoring {folder}")
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        self.disconnect()
        logger.info("Stopped monitoring")
    
    def _monitor_loop(self, folder: str):
        """Main monitoring loop"""
        while self.running:
            try:
                if not self.client:
                    if not self.connect():
                        time.sleep(30)
                        continue
                
                self.client.select_folder(folder)
                
                # Get unread messages
                messages = self.client.search(['UNSEEN'])
                
                for uid in messages:
                    if uid not in self._processed_uids:
                        self._process_email(uid)
                        self._processed_uids.add(uid)
                
                time.sleep(self.config.EMAIL_CHECK_INTERVAL)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                self.client = None
                time.sleep(30)
    
    def check_emails_once(self, folder: str = "INBOX", limit: int = 10) -> List[Dict]:
        """
        Check emails once and return found links with verification results.
        
        Args:
            folder: Email folder to check
            limit: Maximum number of recent emails to check
            
        Returns:
            List of dictionaries with link and verification info
        """
        results = []
        
        try:
            if not self.client:
                if not self.connect():
                    return results
            
            self.client.select_folder(folder)
            
            # Get recent messages
            messages = self.client.search(['ALL'])
            recent_messages = messages[-limit:] if len(messages) > limit else messages
            
            for uid in recent_messages:
                email_links = self._extract_links_from_email(uid)
                for email_link in email_links:
                    verification = self.verifier.verify_link(email_link.url)
                    results.append({
                        'link': email_link.to_dict(),
                        'verification': verification.to_dict()
                    })
                    
                    if self.on_link_found:
                        self.on_link_found(email_link, verification)
            
        except Exception as e:
            logger.error(f"Error checking emails: {e}")
        
        return results
    
    def _process_email(self, uid: int):
        """Process a single email and verify any links found"""
        try:
            email_links = self._extract_links_from_email(uid)
            
            for email_link in email_links:
                logger.info(f"Found link: {email_link.url}")
                verification = self.verifier.verify_link(email_link.url)
                
                if self.on_link_found:
                    self.on_link_found(email_link, verification)
                    
        except Exception as e:
            logger.error(f"Error processing email {uid}: {e}")
    
    def _extract_links_from_email(self, uid: int) -> List[EmailLink]:
        """Extract all links from an email"""
        links = []
        
        try:
            # Fetch the email
            raw_messages = self.client.fetch([uid], ['RFC822', 'ENVELOPE'])
            if uid not in raw_messages:
                return links
            
            raw_message = raw_messages[uid]
            envelope = raw_message.get(b'ENVELOPE')
            msg = email.message_from_bytes(raw_message[b'RFC822'])
            
            # Get email metadata
            subject = self._decode_header(envelope.subject) if envelope.subject else "No Subject"
            from_addr = ""
            if envelope.from_:
                from_addr = f"{envelope.from_[0].mailbox.decode()}@{envelope.from_[0].host.decode()}"
            
            date = envelope.date if envelope else datetime.now()
            
            # Extract links from email body
            body_links = self._extract_links_from_message(msg)
            
            for url in body_links:
                links.append(EmailLink(
                    url=url,
                    email_subject=subject,
                    email_from=from_addr,
                    email_date=date,
                    email_uid=uid
                ))
                
        except Exception as e:
            logger.error(f"Error extracting links from email {uid}: {e}")
        
        return links
    
    def _extract_links_from_message(self, msg) -> List[str]:
        """Extract links from email message parts"""
        all_links = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                
                if content_type == "text/plain":
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        all_links.extend(self._extract_links_from_text(body))
                    except:
                        pass
                        
                elif content_type == "text/html":
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        all_links.extend(self._extract_links_from_html(body))
                    except:
                        pass
        else:
            content_type = msg.get_content_type()
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                
                if content_type == "text/html":
                    all_links.extend(self._extract_links_from_html(body))
                else:
                    all_links.extend(self._extract_links_from_text(body))
            except:
                pass
        
        # Filter and deduplicate
        unique_links = list(set(all_links))
        
        # Filter out common non-suspicious links (optional)
        filtered_links = [
            link for link in unique_links
            if not self._is_safe_domain(link)
        ]
        
        # If filtering removed all links, return all found links
        return filtered_links if filtered_links else unique_links
    
    def _extract_links_from_text(self, text: str) -> List[str]:
        """Extract links from plain text"""
        matches = self.URL_PATTERN.findall(text)
        # Clean up links
        cleaned = []
        for link in matches:
            # Remove trailing punctuation
            link = link.rstrip('.,;:!?)')
            if link.startswith('www.'):
                link = 'https://' + link
            cleaned.append(link)
        return cleaned
    
    def _extract_links_from_html(self, html: str) -> List[str]:
        """Extract links from HTML content"""
        links = []
        
        # Extract from href attributes
        parser = HTMLLinkExtractor()
        try:
            parser.feed(html)
            links.extend(parser.get_links())
        except:
            pass
        
        # Also extract plain text URLs
        links.extend(self._extract_links_from_text(html))
        
        return list(set(links))
    
    def _decode_header(self, header) -> str:
        """Decode email header"""
        if isinstance(header, bytes):
            header = header.decode('utf-8', errors='ignore')
        decoded_parts = decode_header(str(header))
        result = ""
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                result += part.decode(encoding or 'utf-8', errors='ignore')
            else:
                result += str(part)
        return result
    
    def _is_safe_domain(self, url: str) -> bool:
        """Check if URL is from a known safe domain (to reduce noise)"""
        safe_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'github.com',
            'linkedin.com', 'youtube.com', 'twitter.com', 'facebook.com'
        ]
        
        for domain in safe_domains:
            if domain in url.lower():
                # Only consider safe if it's the actual domain
                # Not something like "google.com.malicious.tk"
                import tldextract
                ext = tldextract.extract(url)
                actual_domain = f"{ext.domain}.{ext.suffix}"
                if actual_domain == domain:
                    return True
        
        return False


if __name__ == "__main__":
    # Quick test
    logging.basicConfig(level=logging.INFO)
    
    def on_link_found(link: EmailLink, result: VerificationResult):
        print(f"\nLink found in email: {link.email_subject}")
        print(f"  URL: {link.url}")
        print(f"  From: {link.email_from}")
        print(f"  Safe: {result.is_safe}")
        print(f"  Risk: {result.risk_level.value}")
    
    monitor = EmailMonitor(on_link_found=on_link_found)
    
    print("Email Monitor Test")
    print("Configure your .env file with email credentials to test.")
