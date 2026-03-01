"""
Domain Scanner - Attack Surface Monitoring Engine
Scans domains for security posture: SSL, headers, DNS, WHOIS, breaches, and technology fingerprinting.
Reuses core analysis from LinkVerifier and extends it for continuous monitoring.

Copyright (c) 2026 SecureLink. All rights reserved.
"""
import ssl
import socket
import hashlib
import logging
import re
import json
import concurrent.futures
from urllib.parse import urlparse
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


# ============== Enums & Data Classes ==============

class SecurityGrade(Enum):
    """Letter grade for overall security posture"""
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class FindingSeverity(Enum):
    """Severity levels for individual findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(Enum):
    """Categories of security findings"""
    SSL = "ssl"
    HEADERS = "headers"
    DNS = "dns"
    WHOIS = "whois"
    TECHNOLOGY = "technology"
    BREACH = "breach"
    CONFIGURATION = "configuration"
    REPUTATION = "reputation"


@dataclass
class SecurityFinding:
    """A single security finding from a scan"""
    category: str
    severity: str
    title: str
    description: str
    remediation: str = ""
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'category': self.category,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'remediation': self.remediation,
            'details': self.details
        }


@dataclass
class DomainScanResult:
    """Complete result of a domain security scan"""
    domain: str
    score: int  # 0-100
    grade: str
    findings: List[SecurityFinding] = field(default_factory=list)
    ssl_info: Dict = field(default_factory=dict)
    headers_info: Dict = field(default_factory=dict)
    dns_info: Dict = field(default_factory=dict)
    whois_info: Dict = field(default_factory=dict)
    technology_info: Dict = field(default_factory=dict)
    breach_info: Dict = field(default_factory=dict)
    port_info: Dict = field(default_factory=dict)
    content_hash: Optional[str] = None
    scan_duration_ms: int = 0
    scanned_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict:
        return {
            'domain': self.domain,
            'score': self.score,
            'grade': self.grade,
            'findings': [f.to_dict() for f in self.findings],
            'findings_summary': self._findings_summary(),
            'ssl_info': self.ssl_info,
            'headers_info': self.headers_info,
            'dns_info': self.dns_info,
            'whois_info': self.whois_info,
            'technology_info': self.technology_info,
            'breach_info': self.breach_info,
            'port_info': self.port_info,
            'scan_duration_ms': self.scan_duration_ms,
            'scanned_at': self.scanned_at.isoformat() if self.scanned_at else None
        }

    def _findings_summary(self) -> Dict:
        """Count findings by severity"""
        summary = {s.value: 0 for s in FindingSeverity}
        for f in self.findings:
            if f.severity in summary:
                summary[f.severity] += 1
        return summary


# ============== Security Headers Reference ==============

# Headers that should be present for good security posture
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'severity': FindingSeverity.HIGH,
        'title': 'Missing HSTS Header',
        'description': 'HTTP Strict Transport Security (HSTS) is not configured. Browsers may connect over insecure HTTP.',
        'remediation': 'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
    },
    'Content-Security-Policy': {
        'severity': FindingSeverity.MEDIUM,
        'title': 'Missing Content Security Policy',
        'description': 'No Content-Security-Policy header found. The site may be vulnerable to XSS attacks.',
        'remediation': "Add a Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'"
    },
    'X-Content-Type-Options': {
        'severity': FindingSeverity.MEDIUM,
        'title': 'Missing X-Content-Type-Options',
        'description': 'Browser MIME-type sniffing is not prevented, which could lead to security issues.',
        'remediation': 'Add the header: X-Content-Type-Options: nosniff'
    },
    'X-Frame-Options': {
        'severity': FindingSeverity.MEDIUM,
        'title': 'Missing X-Frame-Options',
        'description': 'The site can be embedded in iframes, making it vulnerable to clickjacking attacks.',
        'remediation': 'Add the header: X-Frame-Options: DENY (or SAMEORIGIN)'
    },
    'X-XSS-Protection': {
        'severity': FindingSeverity.LOW,
        'title': 'Missing X-XSS-Protection',
        'description': 'Browser XSS filter is not explicitly enabled.',
        'remediation': 'Add the header: X-XSS-Protection: 1; mode=block'
    },
    'Referrer-Policy': {
        'severity': FindingSeverity.LOW,
        'title': 'Missing Referrer-Policy',
        'description': 'No Referrer-Policy set. Sensitive URL paths may leak to third-party sites.',
        'remediation': 'Add the header: Referrer-Policy: strict-origin-when-cross-origin'
    },
    'Permissions-Policy': {
        'severity': FindingSeverity.LOW,
        'title': 'Missing Permissions-Policy',
        'description': 'Browser feature permissions are not restricted.',
        'remediation': 'Add a Permissions-Policy header to restrict browser features like camera, microphone, geolocation.'
    }
}

# Headers that should NOT be present (information disclosure)
LEAKY_HEADERS = {
    'Server': {
        'severity': FindingSeverity.LOW,
        'title': 'Server Version Disclosed',
        'description': 'The Server header reveals web server software/version, aiding attackers in finding known vulnerabilities.',
        'remediation': 'Remove or obfuscate the Server header in your web server configuration.'
    },
    'X-Powered-By': {
        'severity': FindingSeverity.LOW,
        'title': 'Technology Stack Disclosed',
        'description': 'The X-Powered-By header reveals the application framework, helping attackers target known vulnerabilities.',
        'remediation': 'Remove the X-Powered-By header from your application or web server configuration.'
    },
    'X-AspNet-Version': {
        'severity': FindingSeverity.LOW,
        'title': 'ASP.NET Version Disclosed',
        'description': 'The exact ASP.NET version is exposed, which may help attackers find version-specific exploits.',
        'remediation': 'Disable the X-AspNet-Version header in your web.config.'
    }
}

# Common technology fingerprints (header patterns -> technology)
TECH_FINGERPRINTS = {
    'server': {
        r'nginx': 'Nginx',
        r'apache': 'Apache',
        r'cloudflare': 'Cloudflare',
        r'microsoft-iis': 'Microsoft IIS',
        r'litespeed': 'LiteSpeed',
        r'gunicorn': 'Gunicorn (Python)',
        r'express': 'Express.js (Node.js)',
        r'openresty': 'OpenResty',
        r'caddy': 'Caddy',
    },
    'x-powered-by': {
        r'php': 'PHP',
        r'asp\.net': 'ASP.NET',
        r'express': 'Express.js',
        r'next\.js': 'Next.js',
        r'nuxt': 'Nuxt.js',
    },
    'set-cookie': {
        r'wordpress_': 'WordPress',
        r'laravel_session': 'Laravel (PHP)',
        r'django': 'Django (Python)',
        r'rack\.session': 'Ruby on Rails',
        r'connect\.sid': 'Express.js (Node.js)',
        r'PHPSESSID': 'PHP',
        r'ASP\.NET_SessionId': 'ASP.NET',
        r'JSESSIONID': 'Java (Tomcat/Spring)',
    }
}

# IDS port scanning constants
DANGEROUS_PORTS = {22, 23, 445, 3306, 3389, 5432, 5900, 6379, 27017}
IDS_SCAN_PORTS  = [21, 22, 23, 25, 53, 80, 443, 445,
                   3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017]


class DomainScanner:
    """
    Domain security scanner that analyzes the external attack surface of a domain.
    Checks SSL, security headers, DNS configuration, WHOIS info, technology stack,
    and known breaches to produce a security scorecard.
    """

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.session.max_redirects = 5

    def scan_domain(self, domain: str) -> DomainScanResult:
        """
        Run a full security scan on a domain.

        Args:
            domain: The domain to scan (e.g., 'example.com')

        Returns:
            DomainScanResult with score, grade, and all findings
        """
        start_time = datetime.utcnow()
        domain = self._normalize_domain(domain)
        logger.info(f"Starting domain scan for: {domain}")

        findings: List[SecurityFinding] = []
        ssl_info = {}
        headers_info = {}
        dns_info = {}
        whois_info = {}
        technology_info = {}
        breach_info = {}

        # Run independent checks in parallel
        port_info = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            ssl_future     = executor.submit(self._check_ssl, domain)
            headers_future = executor.submit(self._check_headers, domain)
            dns_future     = executor.submit(self._check_dns, domain)
            whois_future   = executor.submit(self._check_whois, domain)
            breach_future  = executor.submit(self._check_breaches, domain)
            port_future    = executor.submit(self._check_ports, domain)

            ssl_info, ssl_findings = ssl_future.result()
            findings.extend(ssl_findings)

            headers_info, headers_findings, tech = headers_future.result()
            findings.extend(headers_findings)
            technology_info = tech

            dns_info, dns_findings = dns_future.result()
            findings.extend(dns_findings)

            whois_info, whois_findings = whois_future.result()
            findings.extend(whois_findings)

            breach_info, breach_findings = breach_future.result()
            findings.extend(breach_findings)

            port_info = port_future.result()

        content_hash = self._compute_content_hash(domain)

        # Calculate score and grade
        score = self._calculate_score(findings)
        grade = self._score_to_grade(score)

        elapsed_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        result = DomainScanResult(
            domain=domain,
            score=score,
            grade=grade,
            findings=findings,
            ssl_info=ssl_info,
            headers_info=headers_info,
            dns_info=dns_info,
            whois_info=whois_info,
            technology_info=technology_info,
            breach_info=breach_info,
            port_info=port_info,
            content_hash=content_hash,
            scan_duration_ms=elapsed_ms,
            scanned_at=datetime.utcnow()
        )

        logger.info(f"Domain scan complete for {domain}: score={score}, grade={grade}, "
                     f"findings={len(findings)}, duration={elapsed_ms}ms")
        return result

    # ================================================================
    #  SSL / TLS
    # ================================================================

    def _check_ssl(self, domain: str) -> Tuple[Dict, List[SecurityFinding]]:
        """Check SSL certificate and TLS configuration"""
        findings = []
        info = {'has_ssl': False}

        try:
            host = domain.split(':')[0]
            context = ssl.create_default_context()

            with socket.create_connection((host, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    raw_cert = ssock.getpeercert(binary_form=True)
                    fingerprint = hashlib.sha256(raw_cert).hexdigest() if raw_cert else None
                    protocol_version = ssock.version()
                    cipher = ssock.cipher()

                    # Parse cert details
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.utcnow()).days
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))

                    # Subject Alternative Names
                    san_list = []
                    for san_type, san_value in cert.get('subjectAltName', []):
                        san_list.append(san_value)

                    info = {
                        'has_ssl': True,
                        'valid': True,
                        'protocol': protocol_version,
                        'cipher': cipher[0] if cipher else None,
                        'cipher_bits': cipher[2] if cipher and len(cipher) > 2 else None,
                        'issuer': issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                        'subject_cn': subject.get('commonName', ''),
                        'san': san_list[:20],  # Limit to 20
                        'not_before': not_before.isoformat(),
                        'not_after': not_after.isoformat(),
                        'days_until_expiry': days_until_expiry,
                        'fingerprint': fingerprint,
                    }

                    # Findings
                    if days_until_expiry < 0:
                        findings.append(SecurityFinding(
                            category=FindingCategory.SSL.value,
                            severity=FindingSeverity.CRITICAL.value,
                            title='SSL Certificate Expired',
                            description=f'The SSL certificate expired {abs(days_until_expiry)} days ago. Visitors will see browser warnings.',
                            remediation='Renew the SSL certificate immediately.',
                            details={'expired_days_ago': abs(days_until_expiry)}
                        ))
                    elif days_until_expiry <= 7:
                        findings.append(SecurityFinding(
                            category=FindingCategory.SSL.value,
                            severity=FindingSeverity.HIGH.value,
                            title='SSL Certificate Expiring Within 7 Days',
                            description=f'The SSL certificate expires in {days_until_expiry} day(s). Renew it urgently to avoid downtime.',
                            remediation='Renew the SSL certificate before it expires.',
                            details={'days_until_expiry': days_until_expiry}
                        ))
                    elif days_until_expiry <= 30:
                        findings.append(SecurityFinding(
                            category=FindingCategory.SSL.value,
                            severity=FindingSeverity.MEDIUM.value,
                            title='SSL Certificate Expiring Soon',
                            description=f'The SSL certificate expires in {days_until_expiry} days. Consider renewing soon.',
                            remediation='Schedule SSL certificate renewal.',
                            details={'days_until_expiry': days_until_expiry}
                        ))

                    # Check for weak protocol
                    if protocol_version and protocol_version in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'):
                        findings.append(SecurityFinding(
                            category=FindingCategory.SSL.value,
                            severity=FindingSeverity.HIGH.value,
                            title=f'Weak TLS Protocol: {protocol_version}',
                            description=f'The server is using {protocol_version}, which is deprecated and insecure.',
                            remediation='Configure the server to use TLS 1.2 or TLS 1.3 only.',
                            details={'protocol': protocol_version}
                        ))

                    # Check cipher strength
                    if cipher and len(cipher) > 2 and cipher[2] < 128:
                        findings.append(SecurityFinding(
                            category=FindingCategory.SSL.value,
                            severity=FindingSeverity.HIGH.value,
                            title='Weak Cipher Suite',
                            description=f'The cipher {cipher[0]} uses only {cipher[2]}-bit encryption, which is considered weak.',
                            remediation='Configure the server to use 128-bit or 256-bit cipher suites.',
                            details={'cipher': cipher[0], 'bits': cipher[2]}
                        ))

        except ssl.SSLCertVerificationError as e:
            info['has_ssl'] = True
            info['valid'] = False
            info['error'] = str(e)[:200]
            findings.append(SecurityFinding(
                category=FindingCategory.SSL.value,
                severity=FindingSeverity.CRITICAL.value,
                title='SSL Certificate Verification Failed',
                description=f'The SSL certificate could not be verified: {str(e)[:150]}',
                remediation='Ensure the SSL certificate is issued by a trusted CA and the domain name matches.',
                details={'error': str(e)[:200]}
            ))

        except (socket.timeout, ConnectionRefusedError):
            info['has_ssl'] = False
            findings.append(SecurityFinding(
                category=FindingCategory.SSL.value,
                severity=FindingSeverity.CRITICAL.value,
                title='No SSL/TLS Available',
                description='Could not establish an HTTPS connection. The site may not support HTTPS at all.',
                remediation='Install an SSL certificate. Free certificates are available from Let\'s Encrypt.',
            ))

        except Exception as e:
            info['has_ssl'] = None
            info['error'] = str(e)[:200]
            logger.warning(f"SSL check error for {domain}: {e}")

        return info, findings

    # ================================================================
    #  HTTP Security Headers + Technology Fingerprinting
    # ================================================================

    def _check_headers(self, domain: str) -> Tuple[Dict, List[SecurityFinding], Dict]:
        """Check HTTP security headers and fingerprint technology"""
        findings = []
        info = {}
        tech = {'detected': []}

        try:
            # Try HTTPS first, fall back to HTTP
            for scheme in ['https', 'http']:
                try:
                    response = self.session.get(
                        f'{scheme}://{domain}',
                        timeout=10,
                        allow_redirects=True,
                        verify=False  # We check SSL separately
                    )
                    break
                except Exception:
                    if scheme == 'http':
                        return info, findings, tech
                    continue

            headers = {k.lower(): v for k, v in response.headers.items()}
            info['status_code'] = response.status_code
            info['final_url'] = response.url
            info['headers_present'] = []
            info['headers_missing'] = []

            # Check if HTTP redirects to HTTPS
            if response.url.startswith('https://'):
                info['redirects_to_https'] = True
            else:
                info['redirects_to_https'] = False
                findings.append(SecurityFinding(
                    category=FindingCategory.HEADERS.value,
                    severity=FindingSeverity.HIGH.value,
                    title='No HTTPS Redirect',
                    description='The site does not redirect HTTP traffic to HTTPS. Visitors may connect insecurely.',
                    remediation='Configure your web server to redirect all HTTP requests to HTTPS (301 redirect).'
                ))

            # Check required security headers
            for header_name, header_info in SECURITY_HEADERS.items():
                header_lower = header_name.lower()
                if header_lower in headers:
                    info['headers_present'].append(header_name)

                    # Validate HSTS max-age
                    if header_lower == 'strict-transport-security':
                        hsts_value = headers[header_lower]
                        max_age_match = re.search(r'max-age=(\d+)', hsts_value)
                        if max_age_match:
                            max_age = int(max_age_match.group(1))
                            info['hsts_max_age'] = max_age
                            if max_age < 31536000:  # Less than 1 year
                                findings.append(SecurityFinding(
                                    category=FindingCategory.HEADERS.value,
                                    severity=FindingSeverity.LOW.value,
                                    title='HSTS Max-Age Too Short',
                                    description=f'HSTS max-age is {max_age} seconds ({max_age // 86400} days). Recommended: at least 1 year (31536000).',
                                    remediation='Increase HSTS max-age to at least 31536000 (1 year).'
                                ))
                        info['hsts_preload'] = 'preload' in hsts_value.lower()
                        info['hsts_include_subdomains'] = 'includesubdomains' in hsts_value.lower()
                else:
                    info['headers_missing'].append(header_name)
                    findings.append(SecurityFinding(
                        category=FindingCategory.HEADERS.value,
                        severity=header_info['severity'].value,
                        title=header_info['title'],
                        description=header_info['description'],
                        remediation=header_info['remediation']
                    ))

            # Check leaky headers
            info['leaky_headers'] = []
            for header_name, header_info in LEAKY_HEADERS.items():
                header_lower = header_name.lower()
                if header_lower in headers:
                    value = headers[header_lower]
                    info['leaky_headers'].append({'header': header_name, 'value': value})
                    findings.append(SecurityFinding(
                        category=FindingCategory.HEADERS.value,
                        severity=header_info['severity'].value,
                        title=header_info['title'],
                        description=f"{header_info['description']} Disclosed value: {value}",
                        remediation=header_info['remediation'],
                        details={'header': header_name, 'value': value}
                    ))

            # Technology fingerprinting
            for header_key, patterns in TECH_FINGERPRINTS.items():
                header_value = headers.get(header_key, '')
                for pattern, tech_name in patterns.items():
                    if re.search(pattern, header_value, re.IGNORECASE):
                        if tech_name not in tech['detected']:
                            tech['detected'].append(tech_name)

            # Check meta generator tag in HTML for CMS detection
            if response.headers.get('content-type', '').startswith('text/html'):
                html_content = response.text[:10000]  # Only check first 10KB
                generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)', html_content, re.IGNORECASE)
                if generator_match:
                    gen = generator_match.group(1).strip()
                    tech['cms'] = gen
                    if gen not in tech['detected']:
                        tech['detected'].append(gen)

        except requests.exceptions.Timeout:
            info['error'] = 'Connection timed out'
        except requests.exceptions.ConnectionError:
            info['error'] = 'Could not connect to domain'
        except Exception as e:
            info['error'] = str(e)[:200]
            logger.warning(f"Headers check error for {domain}: {e}")

        return info, findings, tech

    # ================================================================
    #  DNS Configuration
    # ================================================================

    def _check_dns(self, domain: str) -> Tuple[Dict, List[SecurityFinding]]:
        """Check DNS configuration for security issues"""
        findings = []
        info = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'has_spf': False,
            'has_dmarc': False,
            'has_dkim': False,
            'has_dnssec': False,
        }

        host = domain.split(':')[0]

        # A records
        try:
            a_records = dns.resolver.resolve(host, 'A')
            info['a_records'] = [str(r) for r in a_records]
        except Exception:
            pass

        # AAAA records (IPv6)
        try:
            aaaa_records = dns.resolver.resolve(host, 'AAAA')
            info['aaaa_records'] = [str(r) for r in aaaa_records]
        except Exception:
            pass

        if not info['a_records'] and not info['aaaa_records']:
            findings.append(SecurityFinding(
                category=FindingCategory.DNS.value,
                severity=FindingSeverity.CRITICAL.value,
                title='No DNS A/AAAA Records',
                description='The domain has no A or AAAA records. It will not resolve for visitors.',
                remediation='Add A and/or AAAA DNS records pointing to your server IP address.'
            ))
            return info, findings

        # NS records
        try:
            ns_records = dns.resolver.resolve(host, 'NS')
            info['ns_records'] = [str(r).rstrip('.') for r in ns_records]
        except Exception:
            pass

        # MX records
        try:
            mx_records = dns.resolver.resolve(host, 'MX')
            info['mx_records'] = [{'priority': r.preference, 'host': str(r.exchange).rstrip('.')} for r in mx_records]
        except Exception:
            pass

        # TXT records (SPF, DKIM indicators, DMARC)
        try:
            txt_records = dns.resolver.resolve(host, 'TXT')
            info['txt_records'] = [str(r).strip('"') for r in txt_records]
            for txt in info['txt_records']:
                if txt.startswith('v=spf1'):
                    info['has_spf'] = True
                    info['spf_record'] = txt
        except Exception:
            pass

        # DMARC check (_dmarc.domain)
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{host}', 'TXT')
            for r in dmarc_records:
                txt = str(r).strip('"')
                if txt.startswith('v=DMARC1'):
                    info['has_dmarc'] = True
                    info['dmarc_record'] = txt
                    # Parse DMARC policy
                    policy_match = re.search(r'p=(\w+)', txt)
                    if policy_match:
                        info['dmarc_policy'] = policy_match.group(1)
        except Exception:
            pass

        # Email security findings
        if info['mx_records']:
            if not info['has_spf']:
                findings.append(SecurityFinding(
                    category=FindingCategory.DNS.value,
                    severity=FindingSeverity.HIGH.value,
                    title='Missing SPF Record',
                    description='No SPF (Sender Policy Framework) record found. Attackers can spoof emails from your domain.',
                    remediation='Add a TXT record like: v=spf1 include:_spf.google.com ~all (adjust for your email provider).'
                ))

            if not info['has_dmarc']:
                findings.append(SecurityFinding(
                    category=FindingCategory.DNS.value,
                    severity=FindingSeverity.HIGH.value,
                    title='Missing DMARC Record',
                    description='No DMARC record found. Your domain is vulnerable to email spoofing and phishing impersonation.',
                    remediation='Add a TXT record at _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com'
                ))
            elif info.get('dmarc_policy') == 'none':
                findings.append(SecurityFinding(
                    category=FindingCategory.DNS.value,
                    severity=FindingSeverity.MEDIUM.value,
                    title='DMARC Policy Set to None',
                    description='DMARC is configured but policy is "none", meaning spoofed emails are not blocked.',
                    remediation='Change DMARC policy to p=quarantine or p=reject after monitoring reports.'
                ))

        # DNSSEC check
        try:
            dns.resolver.resolve(host, 'DNSKEY')
            info['has_dnssec'] = True
        except dns.resolver.NoAnswer:
            info['has_dnssec'] = False
            findings.append(SecurityFinding(
                category=FindingCategory.DNS.value,
                severity=FindingSeverity.LOW.value,
                title='DNSSEC Not Enabled',
                description='DNSSEC is not configured. DNS responses could be spoofed.',
                remediation='Enable DNSSEC with your DNS provider to protect against DNS spoofing.'
            ))
        except Exception:
            pass

        return info, findings

    # ================================================================
    #  WHOIS Information
    # ================================================================

    def _check_whois(self, domain: str) -> Tuple[Dict, List[SecurityFinding]]:
        """Check WHOIS information for the domain"""
        findings = []
        info = {'available': False}

        if not WHOIS_AVAILABLE:
            return info, findings

        try:
            host = domain.split(':')[0]
            ext = tldextract.extract(host)
            registered_domain = f"{ext.domain}.{ext.suffix}"

            w = whois.whois(registered_domain)

            if w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                domain_age_days = (datetime.now() - creation).days
                info['creation_date'] = creation.isoformat() if creation else None
                info['domain_age_days'] = domain_age_days

                if domain_age_days < 30:
                    findings.append(SecurityFinding(
                        category=FindingCategory.WHOIS.value,
                        severity=FindingSeverity.MEDIUM.value,
                        title='Very New Domain',
                        description=f'Domain was registered only {domain_age_days} days ago. New domains have higher risk.',
                        remediation='This is informational. New domains are not inherently insecure.',
                        details={'domain_age_days': domain_age_days}
                    ))

            if w.expiration_date:
                expiration = w.expiration_date
                if isinstance(expiration, list):
                    expiration = expiration[0]
                days_until_expiry = (expiration - datetime.now()).days
                info['expiration_date'] = expiration.isoformat() if expiration else None
                info['days_until_domain_expiry'] = days_until_expiry

                if days_until_expiry < 0:
                    findings.append(SecurityFinding(
                        category=FindingCategory.WHOIS.value,
                        severity=FindingSeverity.HIGH.value,
                        title='Domain Registration Expired',
                        description=f'The domain registration expired {abs(days_until_expiry)} days ago.',
                        remediation='Renew the domain registration immediately to prevent hijacking.'
                    ))
                elif days_until_expiry < 30:
                    findings.append(SecurityFinding(
                        category=FindingCategory.WHOIS.value,
                        severity=FindingSeverity.MEDIUM.value,
                        title='Domain Registration Expiring Soon',
                        description=f'Domain registration expires in {days_until_expiry} days.',
                        remediation='Renew the domain registration and enable auto-renewal.'
                    ))

            if w.registrar:
                info['registrar'] = str(w.registrar)
            if w.name_servers:
                ns = w.name_servers
                if isinstance(ns, list):
                    info['name_servers'] = [str(n).lower() for n in ns]
                else:
                    info['name_servers'] = [str(ns).lower()]

            info['available'] = True

        except Exception as e:
            info['error'] = str(e)[:200]
            logger.warning(f"WHOIS check error for {domain}: {e}")

        return info, findings

    # ================================================================
    #  Breach Monitoring (HaveIBeenPwned domain search)
    # ================================================================

    def _check_breaches(self, domain: str) -> Tuple[Dict, List[SecurityFinding]]:
        """Check domain for known data breaches"""
        findings = []
        info = {'checked': False, 'breaches': []}

        import os
        api_key = os.environ.get('HIBP_API_KEY')

        if not api_key:
            info['demo_mode'] = True
            info['message'] = 'Breach monitoring requires a HaveIBeenPwned API key.'
            return info, findings

        try:
            # Search for breaches associated with this domain
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breaches",
                headers={
                    "hibp-api-key": api_key,
                    "User-Agent": "SecureLink-DomainScanner"
                },
                timeout=10
            )

            if response.status_code == 200:
                all_breaches = response.json()
                # Filter breaches that match this domain
                domain_breaches = [b for b in all_breaches if b.get('Domain', '').lower() == domain.lower()]

                info['checked'] = True
                info['breaches'] = [{
                    'name': b.get('Name'),
                    'date': b.get('BreachDate'),
                    'pwn_count': b.get('PwnCount', 0),
                    'data_classes': b.get('DataClasses', []),
                    'description': b.get('Description', '')[:200]
                } for b in domain_breaches]

                if domain_breaches:
                    total_accounts = sum(b.get('PwnCount', 0) for b in domain_breaches)
                    findings.append(SecurityFinding(
                        category=FindingCategory.BREACH.value,
                        severity=FindingSeverity.HIGH.value,
                        title=f'{len(domain_breaches)} Known Data Breach(es)',
                        description=f'This domain has been involved in {len(domain_breaches)} known data breach(es) affecting approximately {total_accounts:,} accounts.',
                        remediation='Review breached data types, force password resets for affected accounts, and implement additional security controls.',
                        details={'breach_count': len(domain_breaches), 'total_accounts': total_accounts}
                    ))

        except Exception as e:
            info['error'] = str(e)[:200]
            logger.warning(f"Breach check error for {domain}: {e}")

        return info, findings

    # ================================================================
    #  IDS Checks
    # ================================================================

    def _check_ports(self, domain: str) -> Dict:
        """Probe IDS_SCAN_PORTS and return list of open ports."""
        host = domain.split(':')[0]

        def probe(port):
            try:
                with socket.create_connection((host, port), timeout=2):
                    return port
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            results = ex.map(probe, IDS_SCAN_PORTS)

        open_ports = sorted(p for p in results if p is not None)
        return {'open_ports': open_ports}

    def _compute_content_hash(self, domain: str) -> Optional[str]:
        """Hash stable page elements (title, h1, meta description) for defacement detection."""
        import re
        for scheme in ('https', 'http'):
            try:
                resp = requests.get(
                    f'{scheme}://{domain}',
                    timeout=10,
                    allow_redirects=True,
                    headers={'User-Agent': 'SecureLink-IDS/1.0'},
                    verify=False
                )
                html = resp.text
                title_m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
                h1_m    = re.search(r'<h1[^>]*>(.*?)</h1>',    html, re.IGNORECASE | re.DOTALL)
                desc_m  = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
                                    html, re.IGNORECASE)
                t  = re.sub(r'<[^>]+>', '', title_m.group(1)).strip() if title_m else ''
                h1 = re.sub(r'<[^>]+>', '', h1_m.group(1)).strip()   if h1_m    else ''
                d  = desc_m.group(1).strip()                          if desc_m  else ''
                payload = f'TITLE:{t}|H1:{h1}|DESC:{d}'.encode()
                return hashlib.sha256(payload).hexdigest()
            except Exception:
                continue
        return None

    # ================================================================
    #  Scoring & Grading
    # ================================================================

    def _calculate_score(self, findings: List[SecurityFinding]) -> int:
        """Calculate a 0-100 security score from findings (higher = better)"""
        score = 100

        severity_penalties = {
            FindingSeverity.CRITICAL.value: 25,
            FindingSeverity.HIGH.value: 15,
            FindingSeverity.MEDIUM.value: 8,
            FindingSeverity.LOW.value: 3,
            FindingSeverity.INFO.value: 0,
        }

        for finding in findings:
            penalty = severity_penalties.get(finding.severity, 0)
            score -= penalty

        return max(0, min(100, score))

    def _score_to_grade(self, score: int) -> str:
        """Convert numeric score to letter grade"""
        if score >= 95:
            return SecurityGrade.A_PLUS.value
        elif score >= 80:
            return SecurityGrade.A.value
        elif score >= 65:
            return SecurityGrade.B.value
        elif score >= 50:
            return SecurityGrade.C.value
        elif score >= 35:
            return SecurityGrade.D.value
        else:
            return SecurityGrade.F.value

    # ================================================================
    #  Helpers
    # ================================================================

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain input: strip protocol, paths, whitespace"""
        domain = domain.strip().lower()
        # Remove protocol
        for prefix in ['https://', 'http://']:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        # Remove path
        domain = domain.split('/')[0]
        # Remove port
        domain = domain.split(':')[0]
        # Remove www prefix for consistency
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain


# ============== Convenience Function ==============

def scan_domain(domain: str) -> DomainScanResult:
    """Convenience function to scan a single domain"""
    scanner = DomainScanner()
    return scanner.scan_domain(domain)


if __name__ == "__main__":
    # Quick test
    test_domains = [
        "google.com",
        "github.com",
    ]

    scanner = DomainScanner()
    for domain in test_domains:
        print(f"\n{'='*60}")
        print(f"Scanning: {domain}")
        print(f"{'='*60}")
        result = scanner.scan_domain(domain)
        print(f"  Score: {result.score}/100 (Grade: {result.grade})")
        print(f"  Findings: {len(result.findings)}")
        for f in result.findings:
            print(f"    [{f.severity.upper()}] {f.title}")
        print(f"  SSL: {'Valid' if result.ssl_info.get('valid') else 'Issues'}")
        print(f"  Tech: {', '.join(result.technology_info.get('detected', [])) or 'None detected'}")
        print(f"  Duration: {result.scan_duration_ms}ms")
