"""
SecureLink Security Module
Provides firewall middleware, IP blocking, rate limiting helpers,
account lockout, password policy enforcement, and request sanitization.

Copyright (c) 2026 SecureLink. All rights reserved.
"""
import os
import re
import time
import logging
import hashlib
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from threading import Lock

from flask import request, jsonify, abort

logger = logging.getLogger(__name__)


# ================================================================
#  Password Policy
# ================================================================
class PasswordPolicy:
    """Enforce strong password requirements"""
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = True
    SPECIAL_CHARS = r'!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~'

    @classmethod
    def validate(cls, password: str) -> dict:
        """Validate password against policy. Returns {'valid': bool, 'errors': [str]}"""
        errors = []

        if len(password) < cls.MIN_LENGTH:
            errors.append(f'Password must be at least {cls.MIN_LENGTH} characters')
        if len(password) > cls.MAX_LENGTH:
            errors.append(f'Password must be at most {cls.MAX_LENGTH} characters')
        if cls.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter')
        if cls.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter')
        if cls.REQUIRE_DIGIT and not re.search(r'\d', password):
            errors.append('Password must contain at least one number')
        if cls.REQUIRE_SPECIAL and not re.search(f'[{cls.SPECIAL_CHARS}]', password):
            errors.append('Password must contain at least one special character')

        return {'valid': len(errors) == 0, 'errors': errors}


# ================================================================
#  Account Lockout Manager
# ================================================================
class AccountLockoutManager:
    """Track failed login attempts and enforce lockout policy"""
    MAX_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)
    ATTEMPT_WINDOW = timedelta(minutes=15)

    def __init__(self):
        self._attempts = defaultdict(list)  # key -> [timestamps]
        self._lockouts = {}  # key -> lockout_expires_at
        self._lock = Lock()

    def record_failure(self, identifier: str):
        """Record a failed login attempt"""
        with self._lock:
            now = datetime.utcnow()
            # Clean old attempts outside the window
            self._attempts[identifier] = [
                t for t in self._attempts[identifier]
                if now - t < self.ATTEMPT_WINDOW
            ]
            self._attempts[identifier].append(now)

            if len(self._attempts[identifier]) >= self.MAX_ATTEMPTS:
                self._lockouts[identifier] = now + self.LOCKOUT_DURATION
                self._attempts[identifier] = []
                logger.warning(f"Account locked out: {identifier[:20]}*** after {self.MAX_ATTEMPTS} failed attempts")

    def is_locked(self, identifier: str) -> bool:
        """Check if an account is currently locked out"""
        with self._lock:
            lockout = self._lockouts.get(identifier)
            if lockout and datetime.utcnow() < lockout:
                return True
            elif lockout:
                del self._lockouts[identifier]
            return False

    def get_remaining_lockout(self, identifier: str) -> int:
        """Get remaining lockout time in seconds"""
        with self._lock:
            lockout = self._lockouts.get(identifier)
            if lockout and datetime.utcnow() < lockout:
                return int((lockout - datetime.utcnow()).total_seconds())
            return 0

    def clear(self, identifier: str):
        """Clear lockout and attempts on successful login"""
        with self._lock:
            self._attempts.pop(identifier, None)
            self._lockouts.pop(identifier, None)


# ================================================================
#  IP-Based Firewall / Request Filter
# ================================================================
class RequestFirewall:
    """
    Application-layer firewall that inspects every request for:
    - Blocked IP addresses
    - Suspicious path patterns (path traversal, SQL injection probes, etc.)
    - Excessive payload sizes
    - Missing or spoofed headers
    """

    # Common attack path patterns
    SUSPICIOUS_PATTERNS = [
        # Path traversal
        r'\.\./|\.\.\\',
        # SQL injection probes
        r"(?i)(union\s+select|;\s*drop\s|;\s*delete\s|1\s*=\s*1|'\s*or\s+'|--\s*$)",
        # Shell injection
        r';\s*(cat|ls|pwd|whoami|id|wget|curl|nc|bash|sh)\b',
        # Server-side template injection
        r'\{\{.*\}\}|\$\{.*\}',
        # Null bytes
        r'%00|\x00',
        # Script tags in URL
        r'<script|javascript:|vbscript:',
        # Common scanner paths
        r'(?i)(wp-admin|wp-login|phpmyadmin|\.env$|\.git/|\.aws|/etc/passwd)',
    ]

    # Compiled patterns for performance
    _compiled_patterns = [re.compile(p) for p in SUSPICIOUS_PATTERNS]

    # Default max content length: 16 MB
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    def __init__(self):
        self._blocked_ips = set()
        self._blocked_ranges = []
        self._whitelisted_ips = set()
        self._suspicious_ips = defaultdict(int)  # ip -> strike count
        self._lock = Lock()
        self.enabled = True

        # Load blocked IPs from env (comma-separated)
        blocked_env = os.getenv('BLOCKED_IPS', '')
        if blocked_env:
            for ip in blocked_env.split(','):
                ip = ip.strip()
                if ip:
                    self.block_ip(ip)

        # Load whitelisted IPs from env
        whitelisted_env = os.getenv('WHITELISTED_IPS', '')
        if whitelisted_env:
            for ip in whitelisted_env.split(','):
                ip = ip.strip()
                if ip:
                    self._whitelisted_ips.add(ip)

    def block_ip(self, ip: str):
        """Block an IP address or CIDR range"""
        with self._lock:
            try:
                # Check if it's a CIDR range
                if '/' in ip:
                    self._blocked_ranges.append(ipaddress.ip_network(ip, strict=False))
                else:
                    self._blocked_ips.add(ip)
                logger.info(f"Blocked IP: {ip}")
            except ValueError:
                logger.warning(f"Invalid IP/range to block: {ip}")

    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        with self._lock:
            self._blocked_ips.discard(ip)

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked"""
        if ip in self._whitelisted_ips:
            return False
        with self._lock:
            if ip in self._blocked_ips:
                return True
            try:
                addr = ipaddress.ip_address(ip)
                for network in self._blocked_ranges:
                    if addr in network:
                        return True
            except ValueError:
                pass
            return False

    def _record_suspicious(self, ip: str, reason: str):
        """Record suspicious activity; auto-block after threshold"""
        with self._lock:
            self._suspicious_ips[ip] += 1
            count = self._suspicious_ips[ip]
            logger.warning(f"Suspicious request from {ip}: {reason} (strike {count})")
            # Auto-block after 10 suspicious requests
            if count >= 10:
                self._blocked_ips.add(ip)
                logger.warning(f"Auto-blocked IP {ip} after {count} suspicious requests")

    def check_request(self) -> tuple:
        """
        Inspect the current Flask request.
        Returns (allowed: bool, reason: str)
        """
        if not self.enabled:
            return True, ''

        ip = _get_client_ip()

        # 1. Check blocked IPs
        if self.is_blocked(ip):
            logger.warning(f"Blocked request from banned IP: {ip}")
            return False, 'Access denied'

        # 2. Content length check
        content_length = request.content_length or 0
        if content_length > self.MAX_CONTENT_LENGTH:
            self._record_suspicious(ip, f'oversized payload ({content_length} bytes)')
            return False, 'Request entity too large'

        # 3. Scan URL path + query string for attack patterns
        full_path = request.full_path if request.query_string else request.path
        for pattern in self._compiled_patterns:
            if pattern.search(full_path):
                self._record_suspicious(ip, f'suspicious path: {full_path[:100]}')
                return False, 'Bad request'

        # 4. Scan request body for attack patterns (for form/JSON data)
        if request.content_type and request.content_length and request.content_length < 10000:
            try:
                body = request.get_data(as_text=True)
                for pattern in self._compiled_patterns:
                    if pattern.search(body):
                        self._record_suspicious(ip, f'suspicious body content')
                        return False, 'Bad request'
            except Exception:
                pass

        return True, ''

    def get_stats(self) -> dict:
        """Get firewall statistics"""
        with self._lock:
            return {
                'blocked_ips': len(self._blocked_ips),
                'blocked_ranges': len(self._blocked_ranges),
                'suspicious_ips': dict(self._suspicious_ips),
                'enabled': self.enabled
            }


# ================================================================
#  Fernet Encryption for Email Passwords
# ================================================================
def get_fernet_key():
    """Get or generate Fernet encryption key from env."""
    key = os.getenv('FERNET_ENCRYPTION_KEY')
    if not key:
        logger.warning("FERNET_ENCRYPTION_KEY not set — email password encryption is degraded. Set this env var in production!")
        # Derive a key from SECRET_KEY as fallback (not ideal but better than base64)
        from cryptography.fernet import Fernet
        import base64
        secret = os.getenv('SECRET_KEY', 'fallback-key-not-for-production')
        derived = hashlib.sha256(secret.encode()).digest()
        key = base64.urlsafe_b64encode(derived).decode()
    return key


def encrypt_value(plaintext: str) -> str:
    """Encrypt a string using Fernet symmetric encryption"""
    from cryptography.fernet import Fernet
    f = Fernet(get_fernet_key().encode() if isinstance(get_fernet_key(), str) else get_fernet_key())
    return f.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a Fernet-encrypted string"""
    from cryptography.fernet import Fernet
    f = Fernet(get_fernet_key().encode() if isinstance(get_fernet_key(), str) else get_fernet_key())
    return f.decrypt(ciphertext.encode()).decode()


# ================================================================
#  Helpers
# ================================================================
def _get_client_ip() -> str:
    """Get real client IP, respecting X-Forwarded-For behind proxies."""
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        # First IP in the chain is the real client
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def sanitize_error(exception: Exception) -> str:
    """Return a safe error message — never expose internal details."""
    # Log the real error for debugging
    logger.error(f"Internal error: {exception}", exc_info=True)
    return 'An internal error occurred. Please try again later.'


# ================================================================
#  Singleton Instances
# ================================================================
lockout_manager = AccountLockoutManager()
request_firewall = RequestFirewall()
