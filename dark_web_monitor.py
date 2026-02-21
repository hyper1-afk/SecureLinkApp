"""
Dark Web Monitor - Monitors dark web breach databases for exposed credentials and personal data.

Uses Have I Been Pwned (HIBP) API as primary source, with pluggable architecture for
additional intelligence sources. Monitors emails, usernames, phone numbers, and domains.

Copyright (c) 2026 SecureLink. All rights reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""
import os
import re
import hashlib
import logging
import threading
import time
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from config import Config

logger = logging.getLogger(__name__)


class AssetType(Enum):
    """Types of assets that can be monitored"""
    EMAIL = "email"
    DOMAIN = "domain"
    USERNAME = "username"
    PHONE = "phone"


class AlertSeverity(Enum):
    """Severity levels for dark web alerts"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertCategory(Enum):
    """Categories of dark web findings"""
    DATA_BREACH = "data_breach"
    PASTE_EXPOSURE = "paste_exposure"
    CREDENTIAL_LEAK = "credential_leak"
    DARK_WEB_MENTION = "dark_web_mention"
    COMBO_LIST = "combo_list"


@dataclass
class BreachRecord:
    """Represents a single breach record from HIBP or other sources"""
    name: str
    title: str
    domain: str
    breach_date: Optional[datetime]
    added_date: Optional[datetime]
    modified_date: Optional[datetime]
    pwn_count: int
    description: str
    logo_path: Optional[str]
    data_classes: List[str]
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    is_retired: bool
    is_spam_list: bool
    source: str = "hibp"

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'title': self.title,
            'domain': self.domain,
            'breach_date': self.breach_date.isoformat() if self.breach_date else None,
            'added_date': self.added_date.isoformat() if self.added_date else None,
            'modified_date': self.modified_date.isoformat() if self.modified_date else None,
            'pwn_count': self.pwn_count,
            'description': self.description,
            'logo_path': self.logo_path,
            'data_classes': self.data_classes,
            'is_verified': self.is_verified,
            'is_fabricated': self.is_fabricated,
            'is_sensitive': self.is_sensitive,
            'is_retired': self.is_retired,
            'is_spam_list': self.is_spam_list,
            'source': self.source
        }


@dataclass
class PasteRecord:
    """Represents paste site exposure"""
    source: str
    paste_id: str
    title: Optional[str]
    date: Optional[datetime]
    email_count: int

    def to_dict(self) -> Dict:
        return {
            'source': self.source,
            'paste_id': self.paste_id,
            'title': self.title,
            'date': self.date.isoformat() if self.date else None,
            'email_count': self.email_count
        }


class DarkWebMonitor:
    """
    Dark Web Monitoring Service.

    Checks email addresses, domains, and other assets against:
    - Have I Been Pwned (HIBP) breach database
    - HIBP paste monitoring
    - Password hash checking (k-Anonymity model)

    Architecture supports adding additional sources (Intelligence X, LeakCheck, etc.)
    """

    HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
    HIBP_PASSWORD_API = "https://api.pwnedpasswords.com"
    USER_AGENT = "SecureLink-DarkWebMonitor/1.0"

    # Rate limiting: HIBP allows 1 req per 1.5s on free tier, 10 req/s on paid
    RATE_LIMIT_DELAY = 1.6  # seconds between requests (free tier safe)

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.hibp_api_key = getattr(self.config, 'HIBP_API_KEY', '') or os.getenv('HIBP_API_KEY', '')
        self._last_request_time = 0
        self._lock = threading.Lock()

    def _rate_limit(self):
        """Enforce rate limiting between API calls"""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self.RATE_LIMIT_DELAY:
                time.sleep(self.RATE_LIMIT_DELAY - elapsed)
            self._last_request_time = time.time()

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers for HIBP API"""
        headers = {
            'User-Agent': self.USER_AGENT,
            'Accept': 'application/json'
        }
        if self.hibp_api_key:
            headers['hibp-api-key'] = self.hibp_api_key
        return headers

    # ========================
    # Breach Checking
    # ========================

    def check_email_breaches(self, email: str, include_unverified: bool = True) -> Tuple[List[BreachRecord], Optional[str]]:
        """
        Check if an email has appeared in known data breaches.

        Args:
            email: Email address to check
            include_unverified: Include unverified breaches

        Returns:
            Tuple of (list of BreachRecords, error message or None)
        """
        self._rate_limit()

        try:
            params = {
                'truncateResponse': 'false',
                'includeUnverified': str(include_unverified).lower()
            }

            response = requests.get(
                f"{self.HIBP_API_BASE}/breachedaccount/{requests.utils.quote(email)}",
                headers=self._get_headers(),
                params=params,
                timeout=15
            )

            if response.status_code == 200:
                breaches = []
                for b in response.json():
                    breaches.append(BreachRecord(
                        name=b.get('Name', ''),
                        title=b.get('Title', ''),
                        domain=b.get('Domain', ''),
                        breach_date=self._parse_date(b.get('BreachDate')),
                        added_date=self._parse_datetime(b.get('AddedDate')),
                        modified_date=self._parse_datetime(b.get('ModifiedDate')),
                        pwn_count=b.get('PwnCount', 0),
                        description=b.get('Description', ''),
                        logo_path=b.get('LogoPath'),
                        data_classes=b.get('DataClasses', []),
                        is_verified=b.get('IsVerified', False),
                        is_fabricated=b.get('IsFabricated', False),
                        is_sensitive=b.get('IsSensitive', False),
                        is_retired=b.get('IsRetired', False),
                        is_spam_list=b.get('IsSpamList', False)
                    ))
                return breaches, None

            elif response.status_code == 404:
                # No breaches found - good news!
                return [], None

            elif response.status_code == 401:
                return [], "API key required for email breach lookups"

            elif response.status_code == 429:
                retry_after = response.headers.get('Retry-After', '2')
                return [], f"Rate limited. Retry after {retry_after}s"

            elif response.status_code == 403:
                return [], "API key invalid or insufficient permissions"

            else:
                return [], f"HIBP API error: {response.status_code}"

        except requests.exceptions.Timeout:
            return [], "Request timed out"
        except requests.exceptions.ConnectionError:
            return [], "Could not connect to breach database"
        except Exception as e:
            logger.error(f"Error checking breaches for {email}: {e}")
            return [], str(e)

    def check_email_pastes(self, email: str) -> Tuple[List[PasteRecord], Optional[str]]:
        """
        Check if an email has appeared in paste sites (Pastebin, etc.).

        Args:
            email: Email address to check

        Returns:
            Tuple of (list of PasteRecords, error message or None)
        """
        self._rate_limit()

        try:
            response = requests.get(
                f"{self.HIBP_API_BASE}/pasteaccount/{requests.utils.quote(email)}",
                headers=self._get_headers(),
                timeout=15
            )

            if response.status_code == 200:
                pastes = []
                for p in response.json():
                    pastes.append(PasteRecord(
                        source=p.get('Source', 'Unknown'),
                        paste_id=p.get('Id', ''),
                        title=p.get('Title'),
                        date=self._parse_datetime(p.get('Date')),
                        email_count=p.get('EmailCount', 0)
                    ))
                return pastes, None

            elif response.status_code == 404:
                return [], None

            elif response.status_code == 401:
                return [], "API key required for paste lookups"

            elif response.status_code == 429:
                return [], "Rate limited"

            else:
                return [], f"HIBP paste API error: {response.status_code}"

        except Exception as e:
            logger.error(f"Error checking pastes for {email}: {e}")
            return [], str(e)

    def check_password_pwned(self, password: str) -> Tuple[int, Optional[str]]:
        """
        Check if a password has been seen in data breaches using k-Anonymity.
        Only sends first 5 chars of SHA-1 hash — password never leaves the client.

        Args:
            password: Password to check

        Returns:
            Tuple of (count of times seen, error message or None)
        """
        try:
            sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1[:5]
            suffix = sha1[5:]

            response = requests.get(
                f"{self.HIBP_PASSWORD_API}/range/{prefix}",
                headers={'User-Agent': self.USER_AGENT},
                timeout=10
            )

            if response.status_code == 200:
                for line in response.text.splitlines():
                    hash_suffix, count = line.split(':')
                    if hash_suffix.strip() == suffix:
                        return int(count.strip()), None
                return 0, None

            return 0, f"Password API error: {response.status_code}"

        except Exception as e:
            logger.error(f"Error checking password: {e}")
            return 0, str(e)

    def check_domain_breaches(self, domain: str) -> Tuple[List[BreachRecord], Optional[str]]:
        """
        Check all breaches associated with a domain.

        Args:
            domain: Domain to check (e.g., 'example.com')

        Returns:
            Tuple of (list of BreachRecords, error message or None)
        """
        self._rate_limit()

        try:
            response = requests.get(
                f"{self.HIBP_API_BASE}/breaches",
                headers=self._get_headers(),
                params={'domain': domain},
                timeout=15
            )

            if response.status_code == 200:
                breaches = []
                for b in response.json():
                    breaches.append(BreachRecord(
                        name=b.get('Name', ''),
                        title=b.get('Title', ''),
                        domain=b.get('Domain', ''),
                        breach_date=self._parse_date(b.get('BreachDate')),
                        added_date=self._parse_datetime(b.get('AddedDate')),
                        modified_date=self._parse_datetime(b.get('ModifiedDate')),
                        pwn_count=b.get('PwnCount', 0),
                        description=b.get('Description', ''),
                        logo_path=b.get('LogoPath'),
                        data_classes=b.get('DataClasses', []),
                        is_verified=b.get('IsVerified', False),
                        is_fabricated=b.get('IsFabricated', False),
                        is_sensitive=b.get('IsSensitive', False),
                        is_retired=b.get('IsRetired', False),
                        is_spam_list=b.get('IsSpamList', False)
                    ))
                return breaches, None

            elif response.status_code == 404:
                return [], None

            else:
                return [], f"Domain breach API error: {response.status_code}"

        except Exception as e:
            logger.error(f"Error checking domain breaches for {domain}: {e}")
            return [], str(e)

    # ========================
    # Full Scan (aggregated)
    # ========================

    def full_scan(self, email: str, check_pastes: bool = True) -> Dict:
        """
        Run a comprehensive dark web scan for an email address.

        Args:
            email: Email to scan
            check_pastes: Also check paste sites

        Returns:
            Dict with breaches, pastes, summary, and risk assessment
        """
        results = {
            'email': email,
            'scan_time': datetime.utcnow().isoformat(),
            'breaches': [],
            'pastes': [],
            'summary': {},
            'risk_level': 'safe',
            'errors': []
        }

        # Check breaches
        breaches, error = self.check_email_breaches(email)
        if error:
            results['errors'].append(f"Breach check: {error}")
        results['breaches'] = [b.to_dict() for b in breaches]

        # Check pastes
        if check_pastes:
            pastes, error = self.check_email_pastes(email)
            if error:
                results['errors'].append(f"Paste check: {error}")
            results['pastes'] = [p.to_dict() for p in pastes]

        # Build summary
        total_breaches = len(breaches)
        total_pastes = len(results['pastes'])
        verified_breaches = sum(1 for b in breaches if b.is_verified)
        sensitive_breaches = sum(1 for b in breaches if b.is_sensitive)

        # Collect all exposed data types
        all_data_classes = set()
        for b in breaches:
            all_data_classes.update(b.data_classes)

        # Count total exposed records
        total_records = sum(b.pwn_count for b in breaches)

        # Risk assessment
        risk_level = self._assess_risk(breaches, results['pastes'])

        results['summary'] = {
            'total_breaches': total_breaches,
            'total_pastes': total_pastes,
            'verified_breaches': verified_breaches,
            'sensitive_breaches': sensitive_breaches,
            'total_records_exposed': total_records,
            'exposed_data_types': sorted(list(all_data_classes)),
            'has_password_exposure': 'Passwords' in all_data_classes,
            'has_financial_exposure': bool(all_data_classes & {
                'Credit cards', 'Bank account numbers', 'Financial data',
                'Payment histories', 'Credit card CVV', 'Partial credit card data'
            }),
            'has_identity_exposure': bool(all_data_classes & {
                'Social security numbers', 'Government issued IDs',
                'Passport numbers', 'Driver\'s licenses', 'National IDs',
                'Tax IDs'
            }),
            'latest_breach': max(
                (b.breach_date for b in breaches if b.breach_date),
                default=None
            ),
            'earliest_breach': min(
                (b.breach_date for b in breaches if b.breach_date),
                default=None
            )
        }

        # Serialize dates in summary
        if results['summary']['latest_breach']:
            results['summary']['latest_breach'] = results['summary']['latest_breach'].isoformat()
        if results['summary']['earliest_breach']:
            results['summary']['earliest_breach'] = results['summary']['earliest_breach'].isoformat()

        results['risk_level'] = risk_level

        return results

    def _assess_risk(self, breaches: List[BreachRecord], pastes: list) -> str:
        """Assess overall risk level based on findings"""
        if not breaches and not pastes:
            return 'safe'

        score = 0

        # Breach count scoring
        verified = [b for b in breaches if b.is_verified and not b.is_spam_list]
        score += len(verified) * 10
        score += len([b for b in breaches if not b.is_verified]) * 3

        # Recent breaches are more dangerous
        one_year_ago = datetime.utcnow() - timedelta(days=365)
        recent = [b for b in breaches if b.breach_date and b.breach_date > one_year_ago]
        score += len(recent) * 15

        # Sensitive data exposure
        all_classes = set()
        for b in breaches:
            all_classes.update(b.data_classes)

        if 'Passwords' in all_classes:
            score += 25
        if all_classes & {'Credit cards', 'Bank account numbers', 'Financial data'}:
            score += 30
        if all_classes & {'Social security numbers', 'Government issued IDs'}:
            score += 40

        # Paste exposure adds risk
        score += len(pastes) * 5

        # Determine level
        if score >= 80:
            return 'critical'
        elif score >= 50:
            return 'high'
        elif score >= 25:
            return 'medium'
        elif score > 0:
            return 'low'
        return 'safe'

    # ========================
    # Utility methods
    # ========================

    @staticmethod
    def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
        """Parse HIBP date format (YYYY-MM-DD)"""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, '%Y-%m-%d')
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
        """Parse HIBP datetime format"""
        if not dt_str:
            return None
        try:
            # Handle various ISO formats
            dt_str = dt_str.replace('Z', '+00:00')
            if '.' in dt_str:
                return datetime.fromisoformat(dt_str.split('.')[0])
            return datetime.fromisoformat(dt_str)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def validate_email(email: str) -> bool:
        """Basic email validation"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Basic domain validation"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        return bool(re.match(pattern, domain))


# Module-level singleton
_monitor_instance = None


def get_dark_web_monitor(config: Config = None) -> DarkWebMonitor:
    """Get or create the dark web monitor singleton"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = DarkWebMonitor(config)
    return _monitor_instance
