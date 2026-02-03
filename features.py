"""
Advanced Features Module for SecureLink
- AI Threat Explanation
- Password Breach Checker
- Slack/Discord/Teams Webhooks
- Threat Geolocation

Copyright (c) 2026 Ryan Haley. All Rights Reserved.
"""
import os
import hashlib
import logging
import httpx
import random
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


# ============== AI Threat Explanation ==============

def get_ai_threat_explanation(url: str = None, risk_score: int = 0, threat_types: List[str] = None, 
                              threat_details: Dict = None, verification_result: Dict = None) -> Optional[str]:
    """Generate a natural language explanation of the threat using Claude"""
    try:
        import anthropic
        
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        if not api_key:
            return None
        
        client = anthropic.Anthropic(api_key=api_key)
        
        # Support both individual params and dict
        if verification_result:
            url = verification_result.get('url', url or 'Unknown URL')
            risk_score = verification_result.get('risk_score', risk_score)
            threat_types = verification_result.get('threats_detected', threat_types or [])
            threat_details = verification_result.get('details', threat_details or {})
        
        if risk_score < 30:
            return None  # No explanation needed for safe links
        
        threat_types = threat_types or []
        threat_details = threat_details or {}
        
        prompt = f"""Analyze this URL security scan and provide a brief, user-friendly explanation (2-3 sentences max) of why this link may be risky. Be specific but not alarmist.

URL: {url}
Risk Score: {risk_score}/100
Threats Detected: {', '.join(threat_types) if threat_types else 'None'}
Details: {threat_details}

Provide a concise explanation for a non-technical user."""

        message = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=150,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        return message.content[0].text.strip()
        
    except Exception as e:
        logger.error(f"AI explanation error: {e}")
        return None


# ============== Password Breach Checker ==============


def check_password_breach(password: str) -> Dict:
    """Check if a password has been exposed in data breaches using k-Anonymity"""
    try:
        import requests
        # Hash the password with SHA-1 (HaveIBeenPwned uses SHA-1)
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Query the API with just the prefix (k-Anonymity)
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "SecureLink-BreachChecker"}
        )

        if response.status_code != 200:
            return {'error': 'Unable to check breach database'}

        # Search for our hash suffix in the response
        hashes = response.text.split('\r\n')
        for line in hashes:
            parts = line.split(':')
            if len(parts) == 2:
                hash_suffix, count = parts
                if hash_suffix == suffix:
                    return {
                        'breached': True,
                        'count': int(count),
                        'message': f'This password has been seen {int(count):,} times in data breaches!'
                    }

        return {
            'breached': False,
            'count': 0,
            'message': 'This password has not been found in known data breaches.'
        }
    except Exception as e:
        logger.error(f"Breach check error: {e}")
        return {'error': str(e)}


def check_email_breach(email: str) -> Dict:
    """Check if an email has been in known data breaches"""
    try:
        import requests
        api_key = os.environ.get('HIBP_API_KEY')

        # If no API key, return a simulated response for demo
        if not api_key:
            # For demo purposes, return a simulated response
            return {
                'breached': False,
                'breaches': [],
                'message': 'Email breach checking requires an API key. Visit haveibeenpwned.com to check manually.',
                'demo_mode': True
            }

        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "SecureLink-BreachChecker"
            },
            params={"truncateResponse": "false"}
        )

        if response.status_code == 404:
            return {
                'breached': False,
                'breaches': [],
                'message': 'Good news! This email has not been found in known data breaches.'
            }
        elif response.status_code == 200:
            breaches = response.json()
            return {
                'breached': True,
                'breaches': [{
                    'name': b.get('Name'),
                    'domain': b.get('Domain'),
                    'date': b.get('BreachDate'),
                    'data_types': b.get('DataClasses', [])
                } for b in breaches],
                'message': f'This email was found in {len(breaches)} data breach(es)!'
            }
        else:
            return {'error': 'Unable to check breach database'}
    except Exception as e:
        logger.error(f"Breach check error: {e}")
        return {'error': str(e)}


# ============== Webhook Notifications ==============

async def send_slack_notification(webhook_url: str, message: Dict) -> bool:
    """Send notification to Slack"""
    try:
        url = message.get('url', 'Unknown URL')
        is_safe = message.get('is_safe', True)
        risk_score = message.get('risk_score', 0)
        user = message.get('user', 'Unknown User')
        
        color = "#36a64f" if is_safe else "#ff0000" if risk_score >= 70 else "#ffa500"
        status = "✅ Safe" if is_safe else "⚠️ Warning" if risk_score < 70 else "🚨 Dangerous"
        
        payload = {
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"SecureLink Alert: {status}"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*URL:*\n{url[:100]}..."},
                            {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_score}/100"},
                            {"type": "mrkdwn", "text": f"*Scanned by:*\n{user}"},
                            {"type": "mrkdwn", "text": f"*Time:*\n{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"}
                        ]
                    }
                ]
            }]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload)
            return response.status_code == 200
            
    except Exception as e:
        logger.error(f"Slack notification error: {e}")
        return False


async def send_discord_notification(webhook_url: str, message: Dict) -> bool:
    """Send notification to Discord"""
    try:
        url = message.get('url', 'Unknown URL')
        is_safe = message.get('is_safe', True)
        risk_score = message.get('risk_score', 0)
        user = message.get('user', 'Unknown User')
        
        color = 0x36a64f if is_safe else 0xff0000 if risk_score >= 70 else 0xffa500
        status = "✅ Safe" if is_safe else "⚠️ Warning" if risk_score < 70 else "🚨 Dangerous"
        
        payload = {
            "embeds": [{
                "title": f"SecureLink Alert: {status}",
                "color": color,
                "fields": [
                    {"name": "URL", "value": url[:100], "inline": False},
                    {"name": "Risk Score", "value": f"{risk_score}/100", "inline": True},
                    {"name": "Scanned by", "value": user, "inline": True}
                ],
                "timestamp": datetime.utcnow().isoformat()
            }]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload)
            return response.status_code in [200, 204]
            
    except Exception as e:
        logger.error(f"Discord notification error: {e}")
        return False


async def send_teams_notification(webhook_url: str, message: Dict) -> bool:
    """Send notification to Microsoft Teams"""
    try:
        url = message.get('url', 'Unknown URL')
        is_safe = message.get('is_safe', True)
        risk_score = message.get('risk_score', 0)
        user = message.get('user', 'Unknown User')
        
        color = "00FF00" if is_safe else "FF0000" if risk_score >= 70 else "FFA500"
        status = "✅ Safe" if is_safe else "⚠️ Warning" if risk_score < 70 else "🚨 Dangerous"
        
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"SecureLink Alert: {status}",
            "sections": [{
                "activityTitle": f"SecureLink Alert: {status}",
                "facts": [
                    {"name": "URL", "value": url[:100]},
                    {"name": "Risk Score", "value": f"{risk_score}/100"},
                    {"name": "Scanned by", "value": user},
                    {"name": "Time", "value": datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
                ],
                "markdown": True
            }]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload)
            return response.status_code == 200
            
    except Exception as e:
        logger.error(f"Teams notification error: {e}")
        return False


# ============== Threat Geolocation ==============

# Sample threat locations for demonstration
THREAT_LOCATIONS = [
    {"country": "RU", "lat": 55.7558, "lng": 37.6173, "city": "Moscow"},
    {"country": "CN", "lat": 39.9042, "lng": 116.4074, "city": "Beijing"},
    {"country": "US", "lat": 40.7128, "lng": -74.0060, "city": "New York"},
    {"country": "BR", "lat": -23.5505, "lng": -46.6333, "city": "São Paulo"},
    {"country": "IN", "lat": 19.0760, "lng": 72.8777, "city": "Mumbai"},
    {"country": "NG", "lat": 6.5244, "lng": 3.3792, "city": "Lagos"},
    {"country": "UA", "lat": 50.4501, "lng": 30.5234, "city": "Kyiv"},
    {"country": "RO", "lat": 44.4268, "lng": 26.1025, "city": "Bucharest"},
    {"country": "PH", "lat": 14.5995, "lng": 120.9842, "city": "Manila"},
    {"country": "ID", "lat": -6.2088, "lng": 106.8456, "city": "Jakarta"},
    {"country": "DE", "lat": 52.5200, "lng": 13.4050, "city": "Berlin"},
    {"country": "GB", "lat": 51.5074, "lng": -0.1278, "city": "London"},
    {"country": "FR", "lat": 48.8566, "lng": 2.3522, "city": "Paris"},
    {"country": "KR", "lat": 37.5665, "lng": 126.9780, "city": "Seoul"},
    {"country": "JP", "lat": 35.6762, "lng": 139.6503, "city": "Tokyo"},
]

THREAT_TYPES = [
    "phishing", "malware", "ransomware", "botnet", "spam",
    "credential_theft", "cryptominer", "exploit_kit", "c2_server"
]


def get_random_threat_location() -> Dict:
    """Get a random threat location for demonstration"""
    location = random.choice(THREAT_LOCATIONS)
    return {
        "country_code": location["country"],
        "lat": location["lat"] + random.uniform(-1, 1),
        "lng": location["lng"] + random.uniform(-1, 1),
        "city": location["city"]
    }


def get_threat_location(url: str) -> Optional[Dict]:
    """
    Attempt to geolocate a URL's server.
    In production, this would use IP geolocation APIs.
    For now, returns random demo data.
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        
        if not domain:
            return None
        
        # In production, you would:
        # 1. Resolve domain to IP
        # 2. Use IP geolocation service (MaxMind, IPInfo, etc.)
        # For demo, return a random location
        return get_random_threat_location()
        
    except Exception as e:
        logger.error(f"Error getting threat location: {e}")
        return None


def generate_demo_threat_events(count: int = 20) -> List[Dict]:
    """Generate demo threat events for the map"""
    events = []
    for _ in range(count):
        location = get_random_threat_location()
        events.append({
            "threat_type": random.choice(THREAT_TYPES),
            "url": f"https://malicious-{random.randint(1000, 9999)}.example.com",
            "country_code": location["country_code"],
            "latitude": location["lat"],
            "longitude": location["lng"],
            "severity": random.choice(["low", "medium", "high"]),
            "description": f"Detected {random.choice(THREAT_TYPES)} activity",
            "created_at": datetime.utcnow().isoformat()
        })
    return events


# ============== URLhaus Integration (Free - No API Key Required) ==============

def fetch_urlhaus_recent_threats(limit: int = 100) -> List[Dict]:
    """
    Fetch recent malware URLs from URLhaus (abuse.ch)
    This is completely free and requires no API key.
    Returns threats with geolocation data.
    """
    try:
        # URLhaus recent URLs API endpoint - uses POST
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        
        response = httpx.post(url, data={'limit': limit}, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        threats = []
        urls_data = data.get('urls', [])[:limit]
        
        for item in urls_data:
            # Map URLhaus threat types to our types
            threat_type = item.get('threat', 'malware').lower()
            if 'phish' in threat_type:
                threat_type = 'phishing'
            elif 'malware' in threat_type:
                threat_type = 'malware'
            
            # Get country from URLhaus data or use random
            country = item.get('country')
            if country:
                location = get_location_for_country(country)
            else:
                location = get_random_threat_location()
            
            threats.append({
                'threat_type': threat_type,
                'url': item.get('url', ''),
                'domain': item.get('host', ''),
                'country_code': location.get('country_code', 'US'),
                'latitude': location.get('lat', 0),
                'longitude': location.get('lng', 0),
                'severity': 'high' if item.get('threat') == 'malware_download' else 'medium',
                'description': f"URLhaus: {item.get('threat', 'Unknown threat')} - {item.get('tags', [])}",
                'source': 'urlhaus',
                'external_id': item.get('id'),
                'date_added': item.get('date_added')
            })
        
        logger.info(f"Fetched {len(threats)} threats from URLhaus")
        return threats
        
    except Exception as e:
        logger.error(f"Error fetching URLhaus data: {e}")
        return []


def get_location_for_country(country_code: str) -> Dict:
    """Get approximate coordinates for a country code"""
    # Common country coordinates (capital/major city)
    country_coords = {
        'US': {'lat': 38.9, 'lng': -77.0, 'country_code': 'US'},
        'CN': {'lat': 39.9, 'lng': 116.4, 'country_code': 'CN'},
        'RU': {'lat': 55.75, 'lng': 37.6, 'country_code': 'RU'},
        'DE': {'lat': 52.5, 'lng': 13.4, 'country_code': 'DE'},
        'GB': {'lat': 51.5, 'lng': -0.12, 'country_code': 'GB'},
        'FR': {'lat': 48.85, 'lng': 2.35, 'country_code': 'FR'},
        'NL': {'lat': 52.37, 'lng': 4.89, 'country_code': 'NL'},
        'JP': {'lat': 35.68, 'lng': 139.69, 'country_code': 'JP'},
        'KR': {'lat': 37.56, 'lng': 126.97, 'country_code': 'KR'},
        'BR': {'lat': -15.8, 'lng': -47.9, 'country_code': 'BR'},
        'IN': {'lat': 28.61, 'lng': 77.21, 'country_code': 'IN'},
        'AU': {'lat': -33.87, 'lng': 151.21, 'country_code': 'AU'},
        'CA': {'lat': 45.42, 'lng': -75.7, 'country_code': 'CA'},
        'IT': {'lat': 41.9, 'lng': 12.5, 'country_code': 'IT'},
        'ES': {'lat': 40.42, 'lng': -3.7, 'country_code': 'ES'},
        'PL': {'lat': 52.23, 'lng': 21.01, 'country_code': 'PL'},
        'UA': {'lat': 50.45, 'lng': 30.52, 'country_code': 'UA'},
        'TR': {'lat': 39.93, 'lng': 32.86, 'country_code': 'TR'},
        'MX': {'lat': 19.43, 'lng': -99.13, 'country_code': 'MX'},
        'ID': {'lat': -6.2, 'lng': 106.85, 'country_code': 'ID'},
        'VN': {'lat': 21.03, 'lng': 105.85, 'country_code': 'VN'},
        'TH': {'lat': 13.75, 'lng': 100.5, 'country_code': 'TH'},
        'SG': {'lat': 1.35, 'lng': 103.82, 'country_code': 'SG'},
        'HK': {'lat': 22.32, 'lng': 114.17, 'country_code': 'HK'},
        'ZA': {'lat': -33.92, 'lng': 18.42, 'country_code': 'ZA'},
        'AE': {'lat': 25.2, 'lng': 55.27, 'country_code': 'AE'},
        'SA': {'lat': 24.69, 'lng': 46.72, 'country_code': 'SA'},
        'EG': {'lat': 30.04, 'lng': 31.24, 'country_code': 'EG'},
        'NG': {'lat': 9.08, 'lng': 7.4, 'country_code': 'NG'},
        'KE': {'lat': -1.29, 'lng': 36.82, 'country_code': 'KE'},
    }
    
    if country_code and country_code.upper() in country_coords:
        coord = country_coords[country_code.upper()]
        # Add slight randomization for visual variety
        return {
            'lat': coord['lat'] + random.uniform(-0.5, 0.5),
            'lng': coord['lng'] + random.uniform(-0.5, 0.5),
            'country_code': country_code.upper()
        }
    
    # Fallback to random location
    return get_random_threat_location()


# ============== AbuseIPDB Integration (Free tier: 1,000 checks/day) ==============

def fetch_abuseipdb_recent_reports(limit: int = 50) -> List[Dict]:
    """
    Fetch recent abuse reports from AbuseIPDB.
    Requires ABUSEIPDB_API_KEY environment variable.
    Free tier: 1,000 checks/day.
    """
    api_key = os.environ.get('ABUSEIPDB_API_KEY')
    if not api_key:
        logger.warning("AbuseIPDB API key not configured")
        return []
    
    try:
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        params = {
            'confidenceMinimum': 75,  # High confidence reports only
            'limit': limit
        }
        
        response = httpx.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        threats = []
        for item in data.get('data', []):
            # Get geolocation for the IP
            ip_info = get_abuseipdb_ip_info(item.get('ipAddress'), api_key)
            
            threats.append({
                'threat_type': 'malicious_ip',
                'url': None,
                'domain': item.get('ipAddress'),
                'country_code': ip_info.get('countryCode', 'US'),
                'latitude': ip_info.get('latitude', 0),
                'longitude': ip_info.get('longitude', 0),
                'severity': 'high' if item.get('abuseConfidenceScore', 0) > 90 else 'medium',
                'description': f"AbuseIPDB: Confidence {item.get('abuseConfidenceScore')}% - {item.get('totalReports', 0)} reports",
                'source': 'abuseipdb',
                'external_id': item.get('ipAddress')
            })
        
        logger.info(f"Fetched {len(threats)} threats from AbuseIPDB")
        return threats
        
    except Exception as e:
        logger.error(f"Error fetching AbuseIPDB data: {e}")
        return []


def get_abuseipdb_ip_info(ip: str, api_key: str) -> Dict:
    """Get detailed info about an IP from AbuseIPDB"""
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        
        response = httpx.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get('data', {})
        
        # Get coordinates from country code if not provided
        country = data.get('countryCode', 'US')
        location = get_location_for_country(country)
        
        return {
            'countryCode': country,
            'latitude': location.get('lat', 0),
            'longitude': location.get('lng', 0),
            'isp': data.get('isp'),
            'domain': data.get('domain'),
            'totalReports': data.get('totalReports', 0)
        }
        
    except Exception as e:
        logger.error(f"Error getting IP info: {e}")
        return {'countryCode': 'US', 'latitude': 38.9, 'longitude': -77.0}


def check_ip_reputation(ip: str) -> Dict:
    """
    Check an IP's reputation using AbuseIPDB.
    Returns abuse confidence score and report count.
    """
    api_key = os.environ.get('ABUSEIPDB_API_KEY')
    if not api_key:
        return {'error': 'AbuseIPDB API key not configured'}
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        response = httpx.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get('data', {})
        
        return {
            'ip': ip,
            'is_public': data.get('isPublic', False),
            'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
            'country_code': data.get('countryCode'),
            'isp': data.get('isp'),
            'domain': data.get('domain'),
            'total_reports': data.get('totalReports', 0),
            'last_reported': data.get('lastReportedAt'),
            'is_whitelisted': data.get('isWhitelisted', False),
            'categories': data.get('reports', [])[:5] if data.get('reports') else []
        }
        
    except Exception as e:
        logger.error(f"Error checking IP reputation: {e}")
        return {'error': str(e)}


# ============== Combined Threat Feed ==============

def fetch_all_threat_feeds() -> List[Dict]:
    """
    Fetch threats from all configured sources.
    Returns combined list of threats for the map.
    """
    all_threats = []
    
    # Always fetch from URLhaus (free, no key needed)
    urlhaus_threats = fetch_urlhaus_recent_threats(limit=50)
    all_threats.extend(urlhaus_threats)
    
    # Fetch from AbuseIPDB if configured
    if os.environ.get('ABUSEIPDB_API_KEY'):
        abuseipdb_threats = fetch_abuseipdb_recent_reports(limit=30)
        all_threats.extend(abuseipdb_threats)
    
    logger.info(f"Total threats fetched from all feeds: {len(all_threats)}")
    return all_threats
