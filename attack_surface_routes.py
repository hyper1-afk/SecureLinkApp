"""
Attack Surface Monitoring - API Routes
All /api/attack-surface/* and /attack-surface page routes.

Copyright (c) 2026 SecureLink. All rights reserved.
"""
import logging
from datetime import datetime
from functools import wraps

from flask import Blueprint, render_template, request, jsonify
from config import Config
from domain_scanner import DomainScanner
from attack_surface_db import AttackSurfaceDB

logger = logging.getLogger(__name__)

# Create Blueprint
attack_surface_bp = Blueprint('attack_surface', __name__)

# Lazy-init services (set in init_attack_surface)
_scanner = None
_db = None
_auth_manager = None


def init_attack_surface(config: Config, auth_manager):
    """Initialize services — called from app.py at startup"""
    global _scanner, _db, _auth_manager
    _scanner = DomainScanner(config)
    _db = AttackSurfaceDB(config)
    _auth_manager = auth_manager


def _get_token():
    """Extract bearer token from request"""
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    return None


def require_auth_as(f):
    """Decorator: require auth and inject user_data with flattened fields"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _get_token()
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        raw = _auth_manager.validate_token(token)
        if not raw:
            return jsonify({'error': 'Invalid or expired token'}), 401
        # Flatten: merge user dict + plan_limits into a single user_data dict
        user_info = raw.get('user', {})
        user_data = {
            'user_id': user_info.get('id'),
            'email': user_info.get('email'),
            'username': user_info.get('username'),
            'subscription_tier': user_info.get('subscription_tier', 'free'),
            'organization_id': user_info.get('organization_id'),
            'plan_limits': raw.get('plan_limits', {}),
        }
        # Team and Enterprise only
        if user_data['subscription_tier'] not in ('team', 'enterprise'):
            return jsonify({
                'error': 'Attack Surface Monitoring is available on the Team and Enterprise plans.',
                'upgrade_required': True
            }), 403
        kwargs['user_data'] = user_data
        return f(*args, **kwargs)
    return decorated


# ================================================================
#  Page Routes
# ================================================================

@attack_surface_bp.route('/attack-surface')
def attack_surface_page():
    """Main attack surface monitoring dashboard page"""
    return render_template('attack_surface/dashboard.html')


@attack_surface_bp.route('/attack-surface/domain/<int:domain_id>')
def domain_detail_page(domain_id):
    """Domain detail/scan results page"""
    return render_template('attack_surface/domain_detail.html', domain_id=domain_id)


# ================================================================
#  API: Domains CRUD
# ================================================================

@attack_surface_bp.route('/api/attack-surface/domains', methods=['GET'])
@require_auth_as
def list_domains(user_data=None):
    """List all monitored domains for the authenticated user"""
    domains = _db.get_user_domains(user_data['user_id'])
    return jsonify({'domains': domains})


@attack_surface_bp.route('/api/attack-surface/domains', methods=['POST'])
@require_auth_as
def add_domain(user_data=None):
    """Add a new domain to monitor"""
    data = request.get_json()
    if not data or not data.get('domain'):
        return jsonify({'error': 'Domain is required'}), 400

    domain = data['domain'].strip().lower()

    # Basic domain validation
    if not domain or len(domain) > 255 or '.' not in domain:
        return jsonify({'error': 'Invalid domain format'}), 400

    # Check plan limits
    current_domains = _db.get_user_domains(user_data['user_id'])
    tier = user_data.get('subscription_tier', 'free')
    limits = _get_domain_limits(tier)
    if len(current_domains) >= limits['max_domains']:
        return jsonify({
            'error': f'Domain limit reached ({limits["max_domains"]}). Upgrade your plan to monitor more domains.',
            'limit': limits['max_domains']
        }), 403

    result = _db.add_domain(
        domain=domain,
        user_id=user_data['user_id'],
        organization_id=user_data.get('organization_id'),
        label=data.get('label'),
        scan_frequency=data.get('scan_frequency', limits['default_frequency']),
    )

    if 'error' in result:
        return jsonify(result), 409

    return jsonify({'domain': result, 'message': 'Domain added successfully'}), 201


@attack_surface_bp.route('/api/attack-surface/domains/<int:domain_id>', methods=['GET'])
@require_auth_as
def get_domain(domain_id, user_data=None):
    """Get details for a specific monitored domain"""
    domain = _db.get_domain(domain_id, user_data['user_id'])
    if not domain:
        return jsonify({'error': 'Domain not found'}), 404
    return jsonify({'domain': domain})


@attack_surface_bp.route('/api/attack-surface/domains/<int:domain_id>', methods=['DELETE'])
@require_auth_as
def remove_domain(domain_id, user_data=None):
    """Remove a domain from monitoring"""
    success = _db.remove_domain(domain_id, user_data['user_id'])
    if not success:
        return jsonify({'error': 'Domain not found'}), 404
    return jsonify({'message': 'Domain removed from monitoring'})


# ================================================================
#  API: Domain Verification
# ================================================================

@attack_surface_bp.route('/api/attack-surface/domains/<int:domain_id>/verify', methods=['POST'])
@require_auth_as
def verify_domain(domain_id, user_data=None):
    """Verify domain ownership via DNS TXT record check"""
    domain_info = _db.get_domain(domain_id, user_data['user_id'])
    if not domain_info:
        return jsonify({'error': 'Domain not found'}), 404

    if domain_info['is_verified']:
        return jsonify({'message': 'Domain is already verified'})

    # Check for DNS TXT verification record
    import dns.resolver
    token = domain_info.get('verification_token', '')
    try:
        txt_records = dns.resolver.resolve(domain_info['domain'], 'TXT')
        for record in txt_records:
            txt_value = str(record).strip('"')
            if txt_value == token:
                _db.verify_domain(domain_id, user_data['user_id'], method='dns_txt')
                return jsonify({'verified': True, 'message': 'Domain verified successfully!'})

        return jsonify({
            'verified': False,
            'message': 'Verification record not found. Add this TXT record to your DNS:',
            'txt_record': token
        }), 400

    except Exception as e:
        return jsonify({
            'verified': False,
            'message': f'Could not check DNS records: {str(e)[:100]}',
            'txt_record': token
        }), 400


@attack_surface_bp.route('/api/attack-surface/domains/<int:domain_id>/verification-token', methods=['GET'])
@require_auth_as
def get_verification_token(domain_id, user_data=None):
    """Get the DNS TXT verification token for a domain"""
    domain_info = _db.get_domain(domain_id, user_data['user_id'])
    if not domain_info:
        return jsonify({'error': 'Domain not found'}), 404

    return jsonify({
        'domain': domain_info['domain'],
        'is_verified': domain_info['is_verified'],
        'verification_token': domain_info.get('verification_token', ''),
        'instructions': (
            f"Add a TXT record to your DNS for {domain_info['domain']} with the value shown above. "
            f"Then click 'Verify' to confirm ownership."
        )
    })


# ================================================================
#  API: Scanning
# ================================================================

@attack_surface_bp.route('/api/attack-surface/domains/<int:domain_id>/scan', methods=['POST'])
@require_auth_as
def scan_domain_now(domain_id, user_data=None):
    """Trigger an immediate scan for a domain"""
    domain_info = _db.get_domain(domain_id, user_data['user_id'])
    if not domain_info:
        return jsonify({'error': 'Domain not found'}), 404

    # Run the scan
    result = _scanner.scan_domain(domain_info['domain'])

    # Save results
    scan_id = _db.save_scan(
        monitored_domain_id=domain_id,
        user_id=user_data['user_id'],
        scan_result=result
    )

    return jsonify({
        'scan': result.to_dict(),
        'scan_id': scan_id,
        'message': f'Scan complete. Score: {result.score}/100 (Grade: {result.grade})'
    })


@attack_surface_bp.route('/api/attack-surface/scan-quick', methods=['POST'])
@require_auth_as
def quick_scan(user_data=None):
    """Quick one-off scan of any domain (doesn't need to be added/monitored)"""
    data = request.get_json()
    if not data or not data.get('domain'):
        return jsonify({'error': 'Domain is required'}), 400

    domain = data['domain'].strip().lower()
    result = _scanner.scan_domain(domain)

    return jsonify({
        'scan': result.to_dict(),
        'message': f'Score: {result.score}/100 (Grade: {result.grade})'
    })


# ================================================================
#  API: Scan History & Trending
# ================================================================

@attack_surface_bp.route('/api/attack-surface/domains/<int:domain_id>/scans', methods=['GET'])
@require_auth_as
def get_scan_history(domain_id, user_data=None):
    """Get scan history for a domain"""
    domain_info = _db.get_domain(domain_id, user_data['user_id'])
    if not domain_info:
        return jsonify({'error': 'Domain not found'}), 404

    limit = request.args.get('limit', 30, type=int)
    history = _db.get_scan_history(domain_id, limit=limit)
    return jsonify({'scans': history})


@attack_surface_bp.route('/api/attack-surface/domains/<int:domain_id>/latest', methods=['GET'])
@require_auth_as
def get_latest_scan(domain_id, user_data=None):
    """Get the most recent scan result for a domain"""
    domain_info = _db.get_domain(domain_id, user_data['user_id'])
    if not domain_info:
        return jsonify({'error': 'Domain not found'}), 404

    scan = _db.get_latest_scan(domain_id)
    if not scan:
        return jsonify({'error': 'No scans yet. Run a scan first.'}), 404

    return jsonify({'scan': scan})


@attack_surface_bp.route('/api/attack-surface/domains/<int:domain_id>/trend', methods=['GET'])
@require_auth_as
def get_score_trend(domain_id, user_data=None):
    """Get score trend data for charting"""
    domain_info = _db.get_domain(domain_id, user_data['user_id'])
    if not domain_info:
        return jsonify({'error': 'Domain not found'}), 404

    days = request.args.get('days', 30, type=int)
    trend = _db.get_score_trend(domain_id, days=days)
    return jsonify({'trend': trend, 'domain': domain_info['domain']})


# ================================================================
#  API: Alerts
# ================================================================

@attack_surface_bp.route('/api/attack-surface/alerts', methods=['GET'])
@require_auth_as
def get_alerts(user_data=None):
    """Get alerts for the authenticated user"""
    unread_only = request.args.get('unread', 'false').lower() == 'true'
    alerts = _db.get_user_alerts(user_data['user_id'], unread_only=unread_only)
    unread_count = _db.get_unread_alert_count(user_data['user_id'])
    return jsonify({'alerts': alerts, 'unread_count': unread_count})


@attack_surface_bp.route('/api/attack-surface/alerts/<int:alert_id>/read', methods=['POST'])
@require_auth_as
def mark_alert_read(alert_id, user_data=None):
    """Mark an alert as read"""
    success = _db.mark_alert_read(alert_id, user_data['user_id'])
    if not success:
        return jsonify({'error': 'Alert not found'}), 404
    return jsonify({'message': 'Alert marked as read'})


# ================================================================
#  API: Dashboard
# ================================================================

@attack_surface_bp.route('/api/attack-surface/dashboard', methods=['GET'])
@require_auth_as
def get_dashboard(user_data=None):
    """Get dashboard summary stats"""
    stats = _db.get_dashboard_stats(user_data['user_id'])
    return jsonify(stats)


# ================================================================
#  API: AI Remediation Advice
# ================================================================

@attack_surface_bp.route('/api/attack-surface/domains/<int:domain_id>/ai-advice', methods=['GET'])
@require_auth_as
def get_ai_advice(domain_id, user_data=None):
    """Get AI-generated remediation advice for the latest scan"""
    domain_info = _db.get_domain(domain_id, user_data['user_id'])
    if not domain_info:
        return jsonify({'error': 'Domain not found'}), 404

    scan = _db.get_latest_scan(domain_id)
    if not scan:
        return jsonify({'error': 'No scans yet'}), 404

    # Generate AI advice using Claude
    try:
        import os
        import anthropic

        api_key = os.environ.get('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({'advice': None, 'message': 'AI advice requires an Anthropic API key.'})

        client = anthropic.Anthropic(api_key=api_key)

        findings_text = "\n".join([
            f"- [{f['severity'].upper()}] {f['title']}: {f['description']}"
            for f in scan.get('findings', [])
        ])

        prompt = f"""You are a cybersecurity consultant. A domain security scan was performed on {domain_info['domain']}.

Score: {scan['score']}/100 (Grade: {scan['grade']})

Findings:
{findings_text or 'No findings.'}

Technologies detected: {', '.join(scan.get('technology_info', {}).get('detected', [])) or 'None'}

Provide a prioritized action plan (max 5 items) for the domain owner. Be specific, practical, and non-alarmist. Format as numbered steps. For each step, explain WHY it matters and HOW to fix it."""

        message = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}]
        )

        advice = message.content[0].text.strip()
        return jsonify({'advice': advice, 'domain': domain_info['domain'], 'score': scan['score']})

    except Exception as e:
        logger.error(f"AI advice error: {e}")
        return jsonify({'advice': None, 'error': str(e)[:100]}), 500


# ================================================================
#  API: IDS Alerts
# ================================================================

@attack_surface_bp.route('/api/attack-surface/domains/<int:domain_id>/ids-alerts', methods=['GET'])
@require_auth_as
def get_ids_alerts(domain_id, user_data=None):
    """Get IDS-specific alerts for a monitored domain"""
    domain_info = _db.get_domain(domain_id, user_data['user_id'])
    if not domain_info:
        return jsonify({'error': 'Domain not found'}), 404
    alerts = _db.get_ids_alerts(domain_id)
    return jsonify({'alerts': alerts, 'domain': domain_info})


@attack_surface_bp.route('/api/attack-surface/domains/<int:domain_id>/reset-baseline', methods=['POST'])
@require_auth_as
def reset_baseline(domain_id, user_data=None):
    """Reset IDS baseline from the latest scan"""
    latest_scan = _db.get_latest_scan(domain_id)
    if not latest_scan:
        return jsonify({'error': 'No scan found to use as baseline'}), 404
    updated = _db.reset_baseline_from_scan_record(domain_id, user_data['user_id'], latest_scan)
    if not updated:
        return jsonify({'error': 'Domain not found'}), 404
    return jsonify({'message': 'Baseline reset', 'baseline_set_at': updated.get('baseline_set_at')})


# ================================================================
#  Helpers
# ================================================================

def _get_domain_limits(tier: str) -> dict:
    """Get domain monitoring limits based on subscription tier"""
    if tier == 'team':
        return {
            'max_domains': 5,
            'default_frequency': 'daily',
            'allowed_frequencies': ['daily', 'weekly'],
            'ai_advice': False,
        }
    if tier == 'enterprise':
        return {
            'max_domains': 25,
            'default_frequency': 'daily',
            'allowed_frequencies': ['hourly', 'daily', 'weekly'],
            'ai_advice': True,
        }
    return {
        'max_domains': 0,
        'default_frequency': None,
        'allowed_frequencies': [],
        'ai_advice': False,
    }
