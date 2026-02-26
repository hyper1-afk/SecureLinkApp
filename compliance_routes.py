"""
Security Compliance Center - API Routes
All /api/compliance/* and /compliance page routes.

Copyright (c) 2026 SecureLink. All rights reserved.
"""
import logging
from datetime import datetime
from functools import wraps

from flask import Blueprint, render_template, request, jsonify
from config import Config
from compliance_db import (
    ComplianceDB, COMPLIANCE_CHECKS, FRAMEWORKS,
    CATEGORY_ORDER, POLICY_TEMPLATES,
)

logger = logging.getLogger(__name__)

# Blueprint
compliance_bp = Blueprint('compliance', __name__)

# Lazy-init (set from app.py via init_compliance)
_db: ComplianceDB = None
_auth_manager = None


def init_compliance(config: Config, auth_manager):
    """Initialize compliance services — called from app.py at startup."""
    global _db, _auth_manager
    _db = ComplianceDB(config)
    _auth_manager = auth_manager


# ================================================================
#  Auth helpers  (mirrors attack_surface_routes pattern)
# ================================================================

def _get_token():
    auth = request.headers.get('Authorization', '')
    return auth[7:] if auth.startswith('Bearer ') else None


def _require_auth(f):
    """Require authentication; inject user_data dict."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _get_token()
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        raw = _auth_manager.validate_token(token)
        if not raw:
            return jsonify({'error': 'Invalid or expired token'}), 401
        user_info = raw.get('user', {})
        user_data = {
            'user_id': user_info.get('id'),
            'email': user_info.get('email'),
            'username': user_info.get('username'),
            'subscription_tier': user_info.get('subscription_tier', 'free'),
            'organization_name': user_info.get('full_name', ''),
        }
        # Enterprise only
        if user_data['subscription_tier'] != 'enterprise':
            return jsonify({
                'error': 'Compliance Center is only available to Enterprise plan users.',
                'upgrade_required': True,
            }), 403
        kwargs['user_data'] = user_data
        return f(*args, **kwargs)
    return decorated


# ================================================================
#  Page Route
# ================================================================

@compliance_bp.route('/compliance')
def compliance_page():
    """Render the compliance center dashboard."""
    return render_template('compliance.html')


# ================================================================
#  API: Frameworks & Checks
# ================================================================

@compliance_bp.route('/api/compliance/frameworks', methods=['GET'])
@_require_auth
def get_frameworks(user_data=None):
    """Return available compliance frameworks."""
    return jsonify({'frameworks': list(FRAMEWORKS.values())})


@compliance_bp.route('/api/compliance/checks', methods=['GET'])
@_require_auth
def get_checks(user_data=None):
    """Return all checks with the user's completion status."""
    framework = request.args.get('framework')  # optional filter

    checks = COMPLIANCE_CHECKS
    if framework and framework in FRAMEWORKS:
        checks = [c for c in checks if framework in c['frameworks']]

    user_statuses = _db.get_user_checks(user_data['user_id'])

    enriched = []
    for c in checks:
        status = user_statuses.get(c['id'], {})
        enriched.append({
            **c,
            'is_completed': status.get('is_completed', False),
            'completed_at': status.get('completed_at'),
            'notes': status.get('notes'),
        })

    return jsonify({'checks': enriched, 'categories': CATEGORY_ORDER})


# ================================================================
#  API: Toggle a check
# ================================================================

@compliance_bp.route('/api/compliance/checks/<check_id>', methods=['PUT'])
@_require_auth
def toggle_check(check_id, user_data=None):
    """Mark a check as completed or uncompleted."""
    # Validate check_id
    valid_ids = {c['id'] for c in COMPLIANCE_CHECKS}
    if check_id not in valid_ids:
        return jsonify({'error': 'Unknown check ID'}), 404

    data = request.get_json() or {}
    completed = data.get('completed', True)
    notes = data.get('notes')

    result = _db.toggle_check(user_data['user_id'], check_id, completed, notes)
    return jsonify(result)


# ================================================================
#  API: Score
# ================================================================

@compliance_bp.route('/api/compliance/score', methods=['GET'])
@_require_auth
def get_score(user_data=None):
    """Return overall and per-framework compliance scores."""
    overall = _db.compute_score(user_data['user_id'])
    framework_scores = {}
    for fw_id in FRAMEWORKS:
        framework_scores[fw_id] = _db.compute_score(user_data['user_id'], fw_id)

    category_scores = _db.compute_category_scores(user_data['user_id'])

    return jsonify({
        'overall': overall,
        'frameworks': framework_scores,
        'categories': category_scores,
    })


# ================================================================
#  API: Policy Templates
# ================================================================

@compliance_bp.route('/api/compliance/policies', methods=['GET'])
@_require_auth
def list_policies(user_data=None):
    """List available policy templates (metadata only)."""
    policies = []
    for key, tmpl in POLICY_TEMPLATES.items():
        policies.append({
            'id': key,
            'title': tmpl['title'],
            'filename': tmpl['filename'],
            'icon': tmpl['icon'],
        })
    return jsonify({'policies': policies})


@compliance_bp.route('/api/compliance/policies/<policy_id>', methods=['GET'])
@_require_auth
def get_policy(policy_id, user_data=None):
    """Return a policy template with company name/date filled in."""
    tmpl = POLICY_TEMPLATES.get(policy_id)
    if not tmpl:
        return jsonify({'error': 'Policy template not found'}), 404

    company_name = request.args.get('company', user_data.get('organization_name') or 'Your Company')
    date_str = datetime.utcnow().strftime('%B %d, %Y')

    content = tmpl['content'].format(company_name=company_name, date=date_str)

    return jsonify({
        'id': policy_id,
        'title': tmpl['title'],
        'filename': tmpl['filename'],
        'content': content,
    })


# ================================================================
#  API: Compliance Report (JSON for frontend PDF generation)
# ================================================================

@compliance_bp.route('/api/compliance/report', methods=['GET'])
@_require_auth
def generate_report(user_data=None):
    """Return all data needed to render a compliance posture report."""
    company_name = request.args.get('company', user_data.get('organization_name') or 'Your Company')

    overall = _db.compute_score(user_data['user_id'])
    framework_scores = {fw: _db.compute_score(user_data['user_id'], fw) for fw in FRAMEWORKS}
    category_scores = _db.compute_category_scores(user_data['user_id'])

    user_statuses = _db.get_user_checks(user_data['user_id'])
    completed_checks = [
        c['title'] for c in COMPLIANCE_CHECKS
        if user_statuses.get(c['id'], {}).get('is_completed')
    ]
    pending_checks = [
        c['title'] for c in COMPLIANCE_CHECKS
        if not user_statuses.get(c['id'], {}).get('is_completed')
    ]

    return jsonify({
        'company_name': company_name,
        'generated_at': datetime.utcnow().isoformat(),
        'overall': overall,
        'frameworks': framework_scores,
        'categories': category_scores,
        'completed_checks': completed_checks,
        'pending_checks': pending_checks,
        'total_checks': len(COMPLIANCE_CHECKS),
        'frameworks_meta': FRAMEWORKS,
    })
