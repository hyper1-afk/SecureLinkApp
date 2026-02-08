"""
Support Email Monitor - Monitors support inbox and auto-creates tickets from customer emails.

Copyright (c) 2026 SecureLink. All rights reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""
import re
import email
import logging
import threading
import time
import ssl
from email.header import decode_header
from datetime import datetime
from typing import Optional, Set
from html.parser import HTMLParser

from imapclient import IMAPClient

from config import Config

logger = logging.getLogger(__name__)


class HTMLTextExtractor(HTMLParser):
    """Extract plain text from HTML content"""
    
    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.skip_data = False
        
    def handle_starttag(self, tag, attrs):
        if tag in ['script', 'style']:
            self.skip_data = True
            
    def handle_endtag(self, tag):
        if tag in ['script', 'style']:
            self.skip_data = False
        if tag in ['p', 'br', 'div', 'li', 'tr']:
            self.text_parts.append('\n')
    
    def handle_data(self, data):
        if not self.skip_data:
            self.text_parts.append(data)
    
    def get_text(self) -> str:
        return ''.join(self.text_parts).strip()


class SupportEmailMonitor:
    """
    Monitors the support email inbox and creates tickets from incoming emails.
    """
    
    def __init__(self, config: Config = None):
        """Initialize the support email monitor."""
        self.config = config or Config()
        self.client: Optional[IMAPClient] = None
        self.running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._processed_uids: Set[int] = set()
        self._admin_manager = None
        
    def _get_admin_manager(self):
        """Lazy load admin manager to avoid circular imports"""
        if self._admin_manager is None:
            from admin import get_admin_manager
            self._admin_manager = get_admin_manager(self.config)
        return self._admin_manager
    
    def connect(self) -> bool:
        """Connect to the support email IMAP server."""
        try:
            if not self.config.SUPPORT_IMAP_HOST or not self.config.SUPPORT_EMAIL_ADDRESS:
                logger.warning("Support email not configured")
                return False
            
            # Create SSL context that doesn't verify certificates (needed for some providers like GoDaddy)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            self.client = IMAPClient(
                self.config.SUPPORT_IMAP_HOST,
                port=self.config.SUPPORT_IMAP_PORT,
                ssl=self.config.SUPPORT_IMAP_SSL,
                ssl_context=ssl_context
            )
            
            self.client.login(
                self.config.SUPPORT_EMAIL_ADDRESS,
                self.config.SUPPORT_EMAIL_PASSWORD
            )
            
            self.client.select_folder('INBOX')
            logger.info(f"Connected to support inbox: {self.config.SUPPORT_EMAIL_ADDRESS}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to support inbox: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the IMAP server."""
        if self.client:
            try:
                self.client.logout()
            except:
                pass
            self.client = None
    
    def _decode_header_value(self, value) -> str:
        """Decode email header value to string."""
        if value is None:
            return ""
        
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')
        
        try:
            decoded_parts = decode_header(value)
            result = []
            for part, charset in decoded_parts:
                if isinstance(part, bytes):
                    result.append(part.decode(charset or 'utf-8', errors='replace'))
                else:
                    result.append(str(part))
            return ' '.join(result)
        except:
            return str(value)
    
    def _extract_email_body(self, msg) -> str:
        """Extract the text body from an email message."""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        text = payload.decode(charset, errors='replace')
                        
                        if content_type == "text/plain":
                            body = text
                            break  # Prefer plain text
                        elif content_type == "text/html" and not body:
                            # Extract text from HTML
                            extractor = HTMLTextExtractor()
                            extractor.feed(text)
                            body = extractor.get_text()
                except Exception as e:
                    logger.debug(f"Error extracting part: {e}")
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    body = payload.decode(charset, errors='replace')
                    
                    if msg.get_content_type() == "text/html":
                        extractor = HTMLTextExtractor()
                        extractor.feed(body)
                        body = extractor.get_text()
            except Exception as e:
                logger.debug(f"Error extracting body: {e}")
        
        return body.strip()
    
    def _extract_email_address(self, from_header: str) -> str:
        """Extract just the email address from a From header."""
        # Match email in angle brackets or standalone
        match = re.search(r'<([^>]+)>', from_header)
        if match:
            return match.group(1)
        
        match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', from_header)
        if match:
            return match.group(0)
        
        return from_header
    
    def _extract_sender_name(self, from_header: str) -> str:
        """Extract the sender's name from a From header."""
        # Check for "Name <email>" format
        match = re.match(r'^([^<]+)<', from_header)
        if match:
            name = match.group(1).strip().strip('"\'')
            if name:
                return name
        
        # Fall back to email address
        return self._extract_email_address(from_header).split('@')[0]
    
    def _categorize_email(self, subject: str, body: str) -> str:
        """Attempt to categorize the ticket based on content."""
        text = (subject + " " + body).lower()
        
        if any(word in text for word in ['payment', 'billing', 'charge', 'refund', 'subscription', 'invoice']):
            return 'billing'
        elif any(word in text for word in ['bug', 'error', 'broken', 'not working', "doesn't work", 'crash', 'issue']):
            return 'technical'
        elif any(word in text for word in ['account', 'login', 'password', 'sign in', 'access']):
            return 'account'
        elif any(word in text for word in ['feature', 'suggestion', 'request', 'would be nice', 'add']):
            return 'feature_request'
        else:
            return 'general'
    
    def _determine_priority(self, subject: str, body: str) -> str:
        """Attempt to determine priority based on content."""
        text = (subject + " " + body).lower()
        
        if any(word in text for word in ['urgent', 'emergency', 'critical', 'asap', 'immediately']):
            return 'urgent'
        elif any(word in text for word in ['important', 'serious', 'major', 'broken completely']):
            return 'high'
        else:
            return 'medium'
    
    def check_for_new_emails(self) -> int:
        """Check for new emails and create tickets. Returns number of tickets created."""
        if not self.client:
            if not self.connect():
                return 0
        
        tickets_created = 0
        
        try:
            # Search for unseen emails
            messages = self.client.search(['UNSEEN'])
            
            if not messages:
                return 0
            
            logger.info(f"Found {len(messages)} new emails in support inbox")
            
            # Fetch email data
            for uid, data in self.client.fetch(messages, ['RFC822', 'FLAGS']).items():
                if uid in self._processed_uids:
                    continue
                
                try:
                    raw_email = data[b'RFC822']
                    msg = email.message_from_bytes(raw_email)
                    
                    # Extract email details
                    from_header = self._decode_header_value(msg.get('From', ''))
                    subject = self._decode_header_value(msg.get('Subject', 'No Subject'))
                    body = self._extract_email_body(msg)
                    
                    sender_email = self._extract_email_address(from_header)
                    sender_name = self._extract_sender_name(from_header)
                    
                    # Skip auto-replies and system messages
                    if any(skip in subject.lower() for skip in ['auto-reply', 'automatic reply', 'out of office', 'delivery status', 'undeliverable']):
                        logger.debug(f"Skipping auto-reply: {subject}")
                        self._processed_uids.add(uid)
                        continue
                    
                    # Skip emails from our own domain (prevent loops)
                    if sender_email.endswith('@securelinkapp.com'):
                        logger.debug(f"Skipping internal email from: {sender_email}")
                        self._processed_uids.add(uid)
                        continue
                    
                    # Create the ticket
                    category = self._categorize_email(subject, body)
                    priority = self._determine_priority(subject, body)
                    
                    admin_manager = self._get_admin_manager()
                    result = admin_manager.create_ticket(
                        customer_email=sender_email,
                        customer_name=sender_name,
                        subject=subject[:200],  # Limit subject length
                        description=body[:5000],  # Limit body length
                        category=category,
                        priority=priority,
                        source='email'
                    )
                    
                    if result.get('success'):
                        tickets_created += 1
                        ticket_num = result['ticket'].get('ticket_number', 'N/A')
                        logger.info(f"Created ticket {ticket_num} from email: {subject[:50]}")
                    else:
                        logger.error(f"Failed to create ticket: {result.get('error')}")
                    
                    self._processed_uids.add(uid)
                    
                except Exception as e:
                    logger.error(f"Error processing email UID {uid}: {e}")
                    self._processed_uids.add(uid)
                    continue
            
            return tickets_created
            
        except Exception as e:
            logger.error(f"Error checking for new emails: {e}")
            # Try to reconnect on next check
            self.disconnect()
            return 0
    
    def start_monitoring(self, interval_seconds: int = 60):
        """Start background email monitoring."""
        if self.running:
            logger.warning("Support email monitor already running")
            return
        
        if not self.config.SUPPORT_EMAIL_ADDRESS:
            logger.info("Support email not configured - monitoring disabled")
            return
        
        self.running = True
        
        def monitor_loop():
            logger.info(f"Starting support email monitor (checking every {interval_seconds}s)")
            
            while self.running:
                try:
                    tickets = self.check_for_new_emails()
                    if tickets > 0:
                        logger.info(f"Created {tickets} tickets from emails")
                except Exception as e:
                    logger.error(f"Support email monitor error: {e}")
                
                # Sleep in small intervals to allow clean shutdown
                for _ in range(interval_seconds):
                    if not self.running:
                        break
                    time.sleep(1)
            
            self.disconnect()
            logger.info("Support email monitor stopped")
        
        self._monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop the background email monitoring."""
        self.running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)


# Global instance
_support_monitor: Optional[SupportEmailMonitor] = None


def get_support_monitor(config: Config = None) -> SupportEmailMonitor:
    """Get or create the global support email monitor instance."""
    global _support_monitor
    if _support_monitor is None:
        _support_monitor = SupportEmailMonitor(config)
    return _support_monitor


def start_support_email_monitor(config: Config = None, interval: int = 60):
    """Start the support email monitor."""
    monitor = get_support_monitor(config)
    monitor.start_monitoring(interval)
    return monitor
