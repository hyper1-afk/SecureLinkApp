"""
Dark Web Monitor - Monitors dark web breach databases for exposed credentials and personal data.

Paid email, paste, and domain breach lookups are disabled. Password checks use only the
free Pwned Passwords k-anonymity range endpoint.

Copyright (c) 2026 SecureLink. All rights reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""
import re
import logging
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

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

    Email, paste, and domain breach lookups are disabled to avoid paid API calls.
    Password hash-prefix checking uses the separate free k-anonymity endpoint.
    """

    PWNED_PASSWORDS_API = "https://api.pwnedpasswords.com"
    USER_AGENT = "SecureLink-PasswordCheck/1.0"

    def __init__(self, config=None):
        del config  # Kept for compatibility with existing app initialization.
        self.paid_email_lookups_enabled = False

    # ========================
    # Breach Checking
    # ========================

    def check_email_breaches(self, email: str, include_unverified: bool = True) -> Tuple[List[BreachRecord], Optional[str]]:
        del email, include_unverified
        return [], "Email breach lookups are unavailable; SecureLink does not make paid breach-account API requests."

    def check_email_pastes(self, email: str) -> Tuple[List[PasteRecord], Optional[str]]:
        del email
        return [], "Paste monitoring is unavailable; SecureLink does not make paid paste-search API requests."

    def get_password_hash_range(self, prefix: str) -> Tuple[List[Dict[str, int | str]], Optional[str]]:
        """Fetch a padded k-anonymity range using a five-character SHA-1 prefix."""
        if not isinstance(prefix, str) or not re.fullmatch(r"[A-Fa-f0-9]{5}", prefix):
            return [], "A valid five-character hash prefix is required."

        try:
            response = requests.get(
                f"{self.PWNED_PASSWORDS_API}/range/{prefix.upper()}",
                headers={"User-Agent": self.USER_AGENT, "Add-Padding": "true"},
                timeout=10,
                allow_redirects=False,
            )
            if response.status_code != 200:
                logger.warning("Pwned Passwords range lookup returned HTTP %s", response.status_code)
                return [], "Password lookup is temporarily unavailable."

            suffixes = []
            for line in response.text.splitlines():
                suffix, separator, count = line.strip().partition(":")
                if not separator or not re.fullmatch(r"[A-Fa-f0-9]{35}", suffix):
                    continue
                try:
                    prevalence = int(count)
                except ValueError:
                    continue
                if prevalence >= 0:
                    suffixes.append({"suffix": suffix.upper(), "count": prevalence})
            if not suffixes:
                logger.warning("Pwned Passwords range lookup returned no valid records")
                return [], "Password lookup returned invalid data."
            return suffixes, None
        except requests.RequestException:
            logger.warning("Pwned Passwords range lookup failed")
            return [], "Password lookup is temporarily unavailable."

    def check_domain_breaches(self, domain: str) -> Tuple[List[BreachRecord], Optional[str]]:
        del domain
        return [], "Domain breach lookups are unavailable; SecureLink does not make paid domain-search API requests."

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
            'risk_level': 'unknown',
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
        risk_level = (
            self._assess_risk(breaches, results['pastes'])
            if not results['errors']
            else 'unknown'
        )

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


def get_dark_web_monitor(config=None) -> DarkWebMonitor:
    """Get or create the dark web monitor singleton"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = DarkWebMonitor(config)
    return _monitor_instance
