"""
Link Verification Engine - Core module for analyzing URLs and detecting threats.

Copyright (c) 2026 Ryan Haley. All Rights Reserved.
"""
import re
import ssl
import socket
import hashlib
import logging
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

import requests
import dns.resolver
import tldextract
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

from config import Config

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level classification"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VerificationResult:
    """Result of link verification"""
    url: str
    is_safe: bool
    risk_level: RiskLevel
    risk_score: float  # 0.0 to 1.0
    threats_detected: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)
    verified_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'url': self.url,
            'is_safe': self.is_safe,
            'risk_level': self.risk_level.value,
            'risk_score': round(self.risk_score, 2),
            'threats_detected': self.threats_detected,
            'warnings': self.warnings,
            'details': self.details,
            'verified_at': self.verified_at.isoformat()
        }


class LinkVerifier:
    """
    Main link verification engine that analyzes URLs for potential threats.
    Uses multiple verification methods including pattern analysis, DNS checks,
    SSL verification, and external API services.
    """
    
    # Known phishing patterns and suspicious keywords
    PHISHING_KEYWORDS = [
        'login', 'signin', 'verify', 'account', 'secure', 'update',
        'confirm', 'banking', 'password', 'credential', 'suspend',
        'unusual', 'activity', 'limited', 'restore', 'unlock'
    ]
    
    # Suspicious TLDs often used in phishing
    SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click',
        'link', 'info', 'online', 'site', 'website', 'space', 'tech'
    ]
    
    # Known URL shorteners
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'j.mp', 'su.pr', 'tr.im', 'cli.gs', 'short.to',
        'cutt.ly', 'rebrand.ly', 'tiny.cc', 'shorturl.at'
    ]
    
    # Legitimate domains that are often impersonated
    COMMONLY_IMPERSONATED = [
        'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
        'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'chase',
        'wellsfargo', 'bankofamerica', 'citibank', 'usps', 'fedex', 'ups',
        'irs', 'gov', 'dhl', 'costco', 'walmart', 'ebay', 'yahoo'
    ]
    
    def __init__(self, config: Config = None):
        """Initialize the link verifier with configuration"""
        self.config = config or Config()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def verify_link(self, url: str) -> VerificationResult:
        """
        Main method to verify a link and return comprehensive results.
        
        Args:
            url: The URL to verify
            
        Returns:
            VerificationResult with all analysis details
        """
        logger.info(f"Starting verification for: {url}")
        
        threats = []
        warnings = []
        details = {}
        risk_scores = []
        
        # Normalize URL
        url = self._normalize_url(url)
        parsed = urlparse(url)
        
        # 1. Basic URL structure analysis
        structure_result = self._analyze_url_structure(url, parsed)
        details['structure_analysis'] = structure_result['details']
        risk_scores.append(structure_result['score'])
        threats.extend(structure_result['threats'])
        warnings.extend(structure_result['warnings'])
        
        # 2. Domain analysis
        domain_result = self._analyze_domain(parsed.netloc)
        details['domain_analysis'] = domain_result['details']
        risk_scores.append(domain_result['score'])
        threats.extend(domain_result['threats'])
        warnings.extend(domain_result['warnings'])
        
        # 3. Check for URL shortener
        shortener_result = self._check_url_shortener(url, parsed)
        details['shortener_check'] = shortener_result['details']
        if shortener_result['is_shortener']:
            warnings.append("URL uses a shortening service - actual destination unknown")
            risk_scores.append(0.3)
        
        # 4. SSL/TLS check
        if parsed.scheme == 'https':
            ssl_result = self._check_ssl_certificate(parsed.netloc)
            details['ssl_check'] = ssl_result['details']
            risk_scores.append(ssl_result['score'])
            threats.extend(ssl_result['threats'])
            warnings.extend(ssl_result['warnings'])
        else:
            warnings.append("URL does not use HTTPS encryption")
            risk_scores.append(0.3)
            details['ssl_check'] = {'secure': False, 'reason': 'Not HTTPS'}
        
        # 5. DNS check
        if self.config.ENABLE_DNS_CHECK:
            dns_result = self._check_dns(parsed.netloc)
            details['dns_check'] = dns_result['details']
            risk_scores.append(dns_result['score'])
            threats.extend(dns_result['threats'])
        
        # 6. WHOIS check (if available)
        if self.config.ENABLE_WHOIS_CHECK and WHOIS_AVAILABLE:
            whois_result = self._check_whois(parsed.netloc)
            details['whois_check'] = whois_result['details']
            risk_scores.append(whois_result['score'])
            warnings.extend(whois_result['warnings'])
        
        # 7. Check against VirusTotal (if API key available)
        if self.config.VIRUSTOTAL_API_KEY:
            vt_result = self._check_virustotal(url)
            details['virustotal'] = vt_result['details']
            risk_scores.append(vt_result['score'])
            threats.extend(vt_result['threats'])
        
        # 8. Check against Google Safe Browsing (if API key available)
        if self.config.GOOGLE_SAFE_BROWSING_API_KEY:
            gsb_result = self._check_google_safe_browsing(url)
            details['google_safe_browsing'] = gsb_result['details']
            risk_scores.append(gsb_result['score'])
            threats.extend(gsb_result['threats'])
        
        # Calculate final risk score
        final_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        
        # Adjust score based on threat count
        if len(threats) > 0:
            final_score = max(final_score, 0.6)
        if len(threats) > 2:
            final_score = max(final_score, 0.8)
        
        # Determine risk level
        risk_level = self._calculate_risk_level(final_score)
        is_safe = risk_level in [RiskLevel.SAFE, RiskLevel.LOW]
        
        result = VerificationResult(
            url=url,
            is_safe=is_safe,
            risk_level=risk_level,
            risk_score=final_score,
            threats_detected=list(set(threats)),
            warnings=list(set(warnings)),
            details=details
        )
        
        logger.info(f"Verification complete - Risk: {risk_level.value}, Score: {final_score:.2f}")
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for analysis"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return unquote(url)
    
    def _analyze_url_structure(self, url: str, parsed) -> Dict:
        """Analyze URL structure for suspicious patterns"""
        threats = []
        warnings = []
        details = {}
        score = 0.0
        
        # Check URL length
        if len(url) > 200:
            warnings.append("Unusually long URL")
            score += 0.2
            details['long_url'] = True
        
        # Check for IP address instead of domain
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
            threats.append("URL uses IP address instead of domain name")
            score += 0.5
            details['uses_ip'] = True
        
        # Check for excessive subdomains
        subdomain_count = parsed.netloc.count('.')
        if subdomain_count > 3:
            warnings.append(f"URL has {subdomain_count} subdomain levels")
            score += 0.2
            details['subdomain_count'] = subdomain_count
        
        # Check for @ symbol (credential injection)
        if '@' in url:
            threats.append("URL contains @ symbol - possible credential injection")
            score += 0.6
            details['has_at_symbol'] = True
        
        # Check for suspicious characters
        if re.search(r'[<>{}|\^~\[\]`]', url):
            threats.append("URL contains suspicious characters")
            score += 0.4
            details['suspicious_chars'] = True
        
        # Check for double encoding
        if '%25' in url:
            threats.append("URL appears to be double-encoded")
            score += 0.4
            details['double_encoded'] = True
        
        # Check path for phishing keywords
        path_lower = parsed.path.lower()
        found_keywords = [kw for kw in self.PHISHING_KEYWORDS if kw in path_lower]
        if found_keywords:
            warnings.append(f"URL path contains suspicious keywords: {', '.join(found_keywords)}")
            score += 0.1 * len(found_keywords)
            details['phishing_keywords'] = found_keywords
        
        # Check for suspicious file extensions
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']
        for ext in suspicious_extensions:
            if parsed.path.lower().endswith(ext):
                threats.append(f"URL points to potentially dangerous file type: {ext}")
                score += 0.5
                details['dangerous_extension'] = ext
        
        # Check query parameters for sensitive data patterns
        if parsed.query:
            if re.search(r'(password|passwd|pwd|token|key|secret|auth)', parsed.query.lower()):
                warnings.append("URL may contain sensitive parameters")
                score += 0.2
                details['sensitive_params'] = True
        
        return {
            'score': min(score, 1.0),
            'threats': threats,
            'warnings': warnings,
            'details': details
        }
    
    def _analyze_domain(self, domain: str) -> Dict:
        """Analyze domain for suspicious patterns"""
        threats = []
        warnings = []
        details = {}
        score = 0.0
        
        # Extract domain components
        ext = tldextract.extract(domain)
        details['domain'] = ext.domain
        details['suffix'] = ext.suffix
        details['subdomain'] = ext.subdomain
        
        # Check TLD
        if ext.suffix in self.SUSPICIOUS_TLDS:
            warnings.append(f"Domain uses suspicious TLD: .{ext.suffix}")
            score += 0.3
            details['suspicious_tld'] = True
        
        # Check for brand impersonation
        domain_lower = domain.lower()
        for brand in self.COMMONLY_IMPERSONATED:
            if brand in domain_lower:
                # Check if it's the legitimate domain
                legitimate_patterns = [
                    f"{brand}.com", f"{brand}.org", f"{brand}.net",
                    f"www.{brand}.com", f"{brand}.co.uk", f"{brand}.gov"
                ]
                if not any(domain_lower.endswith(p) or domain_lower == p for p in legitimate_patterns):
                    threats.append(f"Possible impersonation of {brand}")
                    score += 0.6
                    details['impersonation_target'] = brand
        
        # Check for typosquatting patterns
        typo_patterns = [
            (r'(.)\1{2,}', 'repeated characters'),
            (r'[0-9]+[a-z]+[0-9]+', 'mixed numbers and letters'),
            (r'(rn|vv|cl|nn)', 'confusing character combinations')
        ]
        for pattern, desc in typo_patterns:
            if re.search(pattern, ext.domain):
                warnings.append(f"Domain contains {desc} - possible typosquatting")
                score += 0.2
                details['typosquatting_indicator'] = desc
        
        # Check for excessive hyphens
        if ext.domain.count('-') > 2:
            warnings.append("Domain contains excessive hyphens")
            score += 0.2
            details['excessive_hyphens'] = True
        
        # Check domain length
        if len(ext.domain) > 30:
            warnings.append("Unusually long domain name")
            score += 0.1
            details['long_domain'] = True
        
        # Check for all-numeric domain
        if ext.domain.isdigit():
            warnings.append("Domain is entirely numeric")
            score += 0.3
            details['numeric_domain'] = True
        
        return {
            'score': min(score, 1.0),
            'threats': threats,
            'warnings': warnings,
            'details': details
        }
    
    def _check_url_shortener(self, url: str, parsed) -> Dict:
        """Check if URL uses a shortening service"""
        domain = parsed.netloc.lower()
        is_shortener = any(shortener in domain for shortener in self.URL_SHORTENERS)
        
        return {
            'is_shortener': is_shortener,
            'details': {
                'is_shortened': is_shortener,
                'domain': domain
            }
        }
    
    def _check_ssl_certificate(self, domain: str) -> Dict:
        """Check SSL certificate validity"""
        threats = []
        warnings = []
        details = {}
        score = 0.0
        
        try:
            # Remove port if present
            host = domain.split(':')[0]
            
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=self.config.REQUEST_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    details['issuer'] = dict(x[0] for x in cert['issuer'])
                    details['subject'] = dict(x[0] for x in cert['subject'])
                    details['expires'] = not_after.isoformat()
                    details['days_until_expiry'] = days_until_expiry
                    details['valid'] = True
                    
                    if days_until_expiry < 0:
                        threats.append("SSL certificate has expired")
                        score = 0.7
                    elif days_until_expiry < 7:
                        warnings.append("SSL certificate expires soon")
                        score = 0.2
                    
        except ssl.SSLCertVerificationError as e:
            threats.append(f"SSL certificate verification failed: {str(e)[:100]}")
            details['valid'] = False
            details['error'] = str(e)[:100]
            score = 0.6
        except Exception as e:
            warnings.append(f"Could not verify SSL certificate: {str(e)[:50]}")
            details['valid'] = None
            details['error'] = str(e)[:50]
            score = 0.3
        
        return {
            'score': score,
            'threats': threats,
            'warnings': warnings,
            'details': details
        }
    
    def _check_dns(self, domain: str) -> Dict:
        """Perform DNS checks on the domain"""
        threats = []
        details = {}
        score = 0.0
        
        try:
            host = domain.split(':')[0]
            
            # A record check
            try:
                a_records = dns.resolver.resolve(host, 'A')
                details['a_records'] = [str(r) for r in a_records]
            except:
                details['a_records'] = []
            
            # MX record check
            try:
                mx_records = dns.resolver.resolve(host, 'MX')
                details['mx_records'] = [str(r) for r in mx_records]
            except:
                details['mx_records'] = []
            
            # If no DNS records found
            if not details.get('a_records'):
                threats.append("Domain has no DNS A records")
                score = 0.5
            
            details['dns_resolved'] = True
            
        except dns.resolver.NXDOMAIN:
            threats.append("Domain does not exist (NXDOMAIN)")
            details['dns_resolved'] = False
            score = 0.8
        except Exception as e:
            details['dns_resolved'] = None
            details['error'] = str(e)[:50]
            score = 0.2
        
        return {
            'score': score,
            'threats': threats,
            'details': details
        }
    
    def _check_whois(self, domain: str) -> Dict:
        """Check WHOIS information for the domain"""
        warnings = []
        details = {}
        score = 0.0
        
        try:
            host = domain.split(':')[0]
            ext = tldextract.extract(host)
            registered_domain = f"{ext.domain}.{ext.suffix}"
            
            w = whois.whois(registered_domain)
            
            if w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                
                domain_age = (datetime.now() - creation).days
                details['domain_age_days'] = domain_age
                details['creation_date'] = creation.isoformat() if creation else None
                
                # New domains are higher risk
                if domain_age < 30:
                    warnings.append("Domain was registered less than 30 days ago")
                    score = 0.5
                elif domain_age < 90:
                    warnings.append("Domain was registered less than 90 days ago")
                    score = 0.3
                elif domain_age < 365:
                    score = 0.1
            
            if w.registrar:
                details['registrar'] = w.registrar
            
            details['whois_available'] = True
            
        except Exception as e:
            details['whois_available'] = False
            details['error'] = str(e)[:50]
            score = 0.1
        
        return {
            'score': score,
            'warnings': warnings,
            'details': details
        }
    
    def _check_virustotal(self, url: str) -> Dict:
        """Check URL against VirusTotal API"""
        threats = []
        details = {}
        score = 0.0
        
        try:
            # Submit URL for scanning
            headers = {'x-apikey': self.config.VIRUSTOTAL_API_KEY}
            
            # First, get URL ID
            url_id = hashlib.sha256(url.encode()).hexdigest()
            
            response = self.session.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers,
                timeout=self.config.REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values()) if stats else 0
                
                details['malicious_detections'] = malicious
                details['suspicious_detections'] = suspicious
                details['total_scanners'] = total
                details['scan_available'] = True
                
                if malicious > 0:
                    threats.append(f"VirusTotal: {malicious} scanners flagged as malicious")
                    score = min(malicious / 10, 1.0)
                elif suspicious > 0:
                    score = min(suspicious / 20, 0.5)
            else:
                details['scan_available'] = False
                
        except Exception as e:
            details['scan_available'] = False
            details['error'] = str(e)[:50]
        
        return {
            'score': score,
            'threats': threats,
            'details': details
        }
    
    def _check_google_safe_browsing(self, url: str) -> Dict:
        """Check URL against Google Safe Browsing API"""
        threats = []
        details = {}
        score = 0.0
        
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.config.GOOGLE_SAFE_BROWSING_API_KEY}"
            
            payload = {
                "client": {
                    "clientId": "ai-link-verifier",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = self.session.post(
                api_url,
                json=payload,
                timeout=self.config.REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                
                details['threats_found'] = len(matches)
                details['scan_available'] = True
                
                if matches:
                    threat_types = [m.get('threatType') for m in matches]
                    threats.append(f"Google Safe Browsing: {', '.join(threat_types)}")
                    score = 0.9
                    details['threat_types'] = threat_types
            else:
                details['scan_available'] = False
                
        except Exception as e:
            details['scan_available'] = False
            details['error'] = str(e)[:50]
        
        return {
            'score': score,
            'threats': threats,
            'details': details
        }
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
        """Calculate risk level from score"""
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= self.config.HIGH_RISK_THRESHOLD:
            return RiskLevel.HIGH
        elif score >= self.config.MEDIUM_RISK_THRESHOLD:
            return RiskLevel.MEDIUM
        elif score >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE


def verify_link(url: str) -> VerificationResult:
    """Convenience function to verify a single link"""
    verifier = LinkVerifier()
    return verifier.verify_link(url)


if __name__ == "__main__":
    # Quick test
    test_urls = [
        "https://google.com",
        "http://suspicious-paypa1-login.tk/secure",
        "https://microsoft.com"
    ]
    
    verifier = LinkVerifier()
    for url in test_urls:
        result = verifier.verify_link(url)
        print(f"\n{url}")
        print(f"  Safe: {result.is_safe}")
        print(f"  Risk Level: {result.risk_level.value}")
        print(f"  Risk Score: {result.risk_score:.2f}")
        if result.threats_detected:
            print(f"  Threats: {result.threats_detected}")
        if result.warnings:
            print(f"  Warnings: {result.warnings}")
