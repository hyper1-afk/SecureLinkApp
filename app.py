"""
SecureLink - Flask Web Application
Main entry point for the web interface with user authentication.

Copyright (c) 2026 SecureLink. All rights reserved.
This software is proprietary and confidential.
"""
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
from datetime import datetime, timedelta

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import and_

from config import Config
from link_verifier import LinkVerifier, VerificationResult
from dark_web_monitor import DarkWebMonitor, get_dark_web_monitor
from notifications import NotificationService
from database import Database, ForumCategory, ForumPost, ForumComment, ForumVote
from auth import AuthManager, SUBSCRIPTION_PLANS, SubscriptionTier
from weekly_reports import WeeklyReportGenerator, get_report_generator
from payments import PaymentManager, get_payment_manager, PLAN_PRICES
from oauth import init_oauth, get_configured_providers, get_oauth_client, parse_user_info, generate_username_from_email
from cyber_news import get_cyber_news
from admin import get_admin_manager, EmployeeRole
from support_email_monitor import start_support_email_monitor
from attack_surface_routes import attack_surface_bp, init_attack_surface
from compliance_routes import compliance_bp, init_compliance
from scan_scheduler import get_scan_scheduler
from domain_scanner import DomainScanner
from features import (
    get_ai_threat_explanation, check_password_breach, check_email_breach,
    send_slack_notification, send_discord_notification, send_teams_notification,
    get_threat_location, generate_demo_threat_events
)
from security import (
    PasswordPolicy, lockout_manager, request_firewall,
    sanitize_error, _get_client_ip
)
from license import validate_on_startup, get_instance_tier, is_self_hosted
from auth import LicenseKey

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY  # Required for OAuth sessions

# ================================================================
#  Max upload size — reject oversized bodies early (16 MB)
# ================================================================
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# ================================================================
#  Template globals — available in all Jinja2 templates
# ================================================================
@app.context_processor
def inject_globals():
    return {
        'app_name': Config.APP_NAME,
        'app_url': Config.APP_URL,
        'is_self_hosted': is_self_hosted(),
        'instance_tier': get_instance_tier(),
    }

# ================================================================
#  CORS — restrict to our own origins only
# ================================================================
ALLOWED_ORIGINS = [
    'https://securelinkapp.com',
    'https://www.securelinkapp.com',
]
# Allow localhost in development
if Config.DEBUG:
    ALLOWED_ORIGINS += ['http://localhost:5000', 'http://127.0.0.1:5000']

CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# Extension API endpoints must allow chrome-extension:// origins (no credentials)
from flask_cors import cross_origin
EXTENSION_CORS = {'origins': '*', 'supports_credentials': False}

# ================================================================
#  Rate Limiting (flask-limiter)
# ================================================================
def _limiter_key_func():
    """Get client IP for rate limiting, respecting X-Forwarded-For."""
    return _get_client_ip()

limiter = Limiter(
    app=app,
    key_func=_limiter_key_func,
    default_limits=["200 per minute"],           # Global default
    storage_uri="memory://",                      # Use Redis URI in production
    strategy="fixed-window",
)

# ================================================================
#  Firewall — inspect every request before routing
# ================================================================
@app.before_request
def firewall_check():
    """Application-layer firewall: block bad IPs and suspicious requests."""
    allowed, reason = request_firewall.check_request()
    if not allowed:
        logger.warning(f"Firewall blocked {_get_client_ip()}: {reason}")
        return jsonify({'error': reason}), 403


# ================================================================
#  Security Headers — applied to every HTTP response
# ================================================================
@app.after_request
def add_security_headers(response):
    """Add security headers to every response to harden the application."""
    # Enforce HTTPS (HSTS) — 1 year, include subdomains, allow preload list
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    # Content Security Policy — restrict resources tightly
    # 'unsafe-inline' kept for styles (Bootstrap requirement) but removed from scripts where possible
    # Nonce-based CSP would be ideal but requires template changes
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://js.stripe.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.stripe.com; "
        "frame-src https://js.stripe.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "upgrade-insecure-requests;"
    )

    # Prevent MIME-type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Prevent clickjacking — block all framing
    response.headers['X-Frame-Options'] = 'DENY'

    # X-XSS-Protection is deprecated — modern CSP is sufficient
    # Explicitly disable it to avoid edge-case XSS in older IE
    response.headers['X-XSS-Protection'] = '0'

    # Control referrer information sent to other sites
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Restrict browser features/APIs
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=(), '
        'payment=(self), usb=(), magnetometer=(), gyroscope=()'
    )

    # Remove server version disclosure (Flask/Werkzeug)
    response.headers.pop('Server', None)

    # Cache control for authenticated API responses
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'

    # Prevent bfcache on tier-gated pages so the back button can't bypass the
    # client-side subscription check that runs on page load.
    _GATED_PAGES = (
        '/dark-web-monitor', '/compliance', '/organization',
        '/attack-surface', '/shortener', '/domain-alerts',
        '/breach-checker', '/pdf-export',
    )
    if any(request.path == p or request.path.startswith(p + '/') for p in _GATED_PAGES):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'

    return response

# Initialize services
config = Config()
verifier = LinkVerifier(config)
db = Database(config)
notification_service = NotificationService(config)
auth_manager = AuthManager(config)
_domain_scanner = DomainScanner()
report_generator = get_report_generator()
payment_manager = get_payment_manager(config)
admin_manager = get_admin_manager(config)

# Initialize OAuth
oauth = init_oauth(app, config)

# Initialize Attack Surface Monitoring
init_attack_surface(config, auth_manager)
app.register_blueprint(attack_surface_bp)

# Initialize Compliance Center
init_compliance(config, auth_manager)
app.register_blueprint(compliance_bp)

# Initialize Dark Web Monitor
dark_web_monitor = get_dark_web_monitor(config)

# Validate license key on startup (self-hosted instances only)
validate_on_startup()


def get_token_from_request():
    """Extract bearer token from request headers"""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    return None

def require_auth(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        user_data = auth_manager.validate_token(token)
        if not user_data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Add user info to request context
        request.current_user = user_data['user']
        request.plan_limits = user_data['plan_limits']
        
        return f(*args, **kwargs)
    return decorated


def _subscription_is_active(user):
    """Return True if the user's paid subscription has not expired."""
    expires_str = user.get('subscription_expires')
    if not expires_str:
        return True  # No expiry set — treated as active (e.g. lifetime / not yet implemented)
    try:
        from datetime import timezone
        expires_at = datetime.fromisoformat(expires_str)
        # Make both offset-naive for comparison
        if expires_at.tzinfo is not None:
            expires_at = expires_at.replace(tzinfo=None)
        return datetime.utcnow() < expires_at
    except (ValueError, TypeError):
        return False


def require_pro(f):
    """Decorator to require an active Pro (or higher) subscription"""
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        user = request.current_user
        tier = user.get('subscription_tier')
        if tier == SubscriptionTier.FREE.value:
            return jsonify({'error': 'This feature requires a Pro subscription'}), 403
        if not _subscription_is_active(user):
            return jsonify({'error': 'Your subscription has expired. Please renew to access this feature.'}), 403
        return f(*args, **kwargs)
    return decorated


def require_team(f):
    """Decorator to require an active Team (or Enterprise) subscription"""
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        user = request.current_user
        tier = user.get('subscription_tier')
        if tier not in (SubscriptionTier.TEAM.value, SubscriptionTier.ENTERPRISE.value):
            return jsonify({'error': 'This feature requires a Team subscription'}), 403
        if not _subscription_is_active(user):
            return jsonify({'error': 'Your subscription has expired. Please renew to access this feature.'}), 403
        return f(*args, **kwargs)
    return decorated


def require_enterprise(f):
    """Decorator to require an active Enterprise subscription"""
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        user = request.current_user
        tier = user.get('subscription_tier')
        if tier != SubscriptionTier.ENTERPRISE.value:
            return jsonify({'error': 'This feature requires an Enterprise subscription'}), 403
        if not _subscription_is_active(user):
            return jsonify({'error': 'Your subscription has expired. Please renew to access this feature.'}), 403
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Decorator to require admin employee authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        employee_data = admin_manager.validate_employee_token(token)
        if not employee_data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Add employee info to request context
        request.current_employee = employee_data['employee']
        
        return f(*args, **kwargs)
    return decorated


def require_admin_role(required_role: str):
    """Decorator to require specific admin role level"""
    def decorator(f):
        @wraps(f)
        @require_admin
        def decorated(*args, **kwargs):
            role_hierarchy = {'support': 1, 'manager': 2, 'admin': 3}
            user_level = role_hierarchy.get(request.current_employee.get('role'), 0)
            required_level = role_hierarchy.get(required_role, 0)
            
            if user_level < required_level:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ============== Page Routes ==============

@app.route('/')
def welcome():
    """Render the welcome/landing page"""
    return render_template('welcome.html')


@app.route('/home')
def index():
    """Render the main dashboard page"""
    return render_template('index.html')


@app.route('/login')
def login_page():
    """Render the login page"""
    return render_template('login.html')


@app.route('/verify-email')
def verify_email_page():
    """Render the email verification page"""
    token = request.args.get('token', '')
    return render_template('verify_email.html', token=token)


@app.route('/profile')
def profile_page():
    """Render the profile page"""
    return render_template('profile.html')


@app.route('/guide')
def guide_page():
    """Render the user guide page"""
    return render_template('guide.html')


@app.route('/privacy')
def privacy_page():
    """Render the privacy policy page"""
    return render_template('privacy.html')


@app.route('/terms')
def terms_page():
    """Render the terms of service page"""
    return render_template('terms.html')


@app.route('/features')
def features_page():
    """Render the features overview page"""
    return render_template('features.html')


@app.route('/faq')
def faq_page():
    """Render the FAQ page"""
    return render_template('faq.html')


@app.route('/self-host')
def deploy_guide_page():
    """Render the self-hosting guide"""
    return render_template('self_host.html')


@app.route('/pricing')
def pricing_page():
    """Render the pricing page"""
    return render_template('pricing.html')


@app.route('/extension')
def extension_page():
    """Render the browser extension page"""
    return render_template('extension.html')


@app.route('/breach-checker')
def breach_checker_page():
    """Render the breach checker page"""
    return render_template('breach_checker.html')


@app.route('/pdf-export')
def pdf_export_page():
    """Render the Health Check PDF Export page (Pro feature)"""
    return render_template('pdf_export.html')


@app.route('/domain-alerts')
def domain_alerts_page():
    """Render the Domain Score Drop Alerts page (Pro feature)"""
    return render_template('domain_alerts.html')


@app.route('/security-news')
def security_news_page():
    """Render the security news feed page"""
    return render_template('security_news.html')


@app.route('/community')
def community_page():
    """Render the community reports page"""
    return render_template('community.html')


@app.route('/organization')
def organization_page():
    """Render the organization dashboard"""
    return render_template('organization.html')


@app.route('/shortener')
def shortener_page():
    """Render the link shortener page"""
    return render_template('shortener.html')


# ============== Auth Routes ==============

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """Register a new user - requires email verification"""
    data = request.get_json()
    
    email = data.get('email', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    full_name = data.get('full_name', '').strip()
    subscription_tier = data.get('subscription_tier', 'free')
    
    if not email or not username or not password:
        return jsonify({'success': False, 'error': 'Email, username, and password are required'}), 400
    
    # Enforce password policy
    pw_check = PasswordPolicy.validate(password)
    if not pw_check['valid']:
        return jsonify({'success': False, 'error': pw_check['errors'][0]}), 400
    
    result = auth_manager.register(email, username, password, full_name)
    
    # If registration successful, send verification email
    if result.get('success'):
        base_url = request.host_url.rstrip('/')
        verification_token = result.get('verification_token')
        
        # Send verification email
        email_sent = auth_manager._send_verification_email(email, username, verification_token, base_url)
        
        # Store the selected plan in the result so frontend can remind user after verification
        result['selected_plan'] = subscription_tier
        result['email_sent'] = email_sent
        result['requires_verification'] = True
        
        # Don't expose the verification token to the frontend
        if 'verification_token' in result:
            del result['verification_token']
    
    return jsonify(result)


@app.route('/api/auth/verify-email', methods=['POST'])
def verify_email():
    """Verify email address using token"""
    data = request.get_json()
    token = data.get('token', '').strip()
    
    if not token:
        return jsonify({'success': False, 'error': 'Verification token is required'}), 400
    
    result = auth_manager.verify_email(token)

    # Activate any pending org license seats assigned to this email
    if result.get('success') and result.get('user'):
        verified_user = result['user']
        db.activate_pending_org_seats(verified_user['email'], verified_user['id'])

    return jsonify(result)


@app.route('/api/auth/resend-verification', methods=['POST'])
@limiter.limit("3 per minute")
def resend_verification():
    """Resend verification email"""
    data = request.get_json()
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({'success': False, 'error': 'Email is required'}), 400
    
    base_url = request.host_url.rstrip('/')
    result = auth_manager.resend_verification(email, base_url)
    return jsonify(result)


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """Authenticate user and create session"""
    data = request.get_json()
    
    email_or_username = data.get('email_or_username', '').strip()
    password = data.get('password', '')
    remember_me = data.get('remember_me', False)
    
    if not email_or_username or not password:
        return jsonify({'success': False, 'error': 'Credentials required'}), 400
    
    # Check account lockout
    lockout_key = email_or_username.lower()
    if lockout_manager.is_locked(lockout_key):
        remaining = lockout_manager.get_remaining_lockout(lockout_key)
        return jsonify({
            'success': False,
            'error': f'Account temporarily locked. Try again in {remaining // 60 + 1} minutes.',
            'locked': True
        }), 429
    
    result = auth_manager.login(
        email_or_username,
        password,
        remember_me=remember_me,
        device_info=request.headers.get('User-Agent'),
        ip_address=_get_client_ip()
    )
    
    # Track failed attempts
    if not result.get('success'):
        lockout_manager.record_failure(lockout_key)
    else:
        lockout_manager.clear(lockout_key)
    
    return jsonify(result)


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """Logout current session"""
    token = get_token_from_request()
    auth_manager.logout(token)
    return jsonify({'success': True})


@app.route('/api/auth/logout-all', methods=['POST'])
@require_auth
def logout_all():
    """Logout all sessions"""
    user_id = request.current_user['id']
    auth_manager.logout_all_devices(user_id)
    return jsonify({'success': True})


@app.route('/api/auth/delete-account', methods=['DELETE'])
@require_auth
def delete_own_account():
    """Delete the current user's account permanently"""
    user = request.current_user
    user_id = user['id']
    
    # Cancel any active Stripe subscription first
    subscription_id = user.get('stripe_subscription_id')
    if subscription_id and not subscription_id.startswith('demo_'):
        try:
            payment_manager.cancel_subscription(subscription_id, at_period_end=False)
        except Exception as e:
            # Log but don't block deletion if subscription cancel fails
            print(f"Warning: Failed to cancel subscription {subscription_id}: {e}")
    
    result = auth_manager.delete_user(user_id)
    return jsonify(result)


@app.route('/api/auth/validate', methods=['GET'])
def validate_token():
    """Validate a session token"""
    token = get_token_from_request()
    if not token:
        return jsonify({'valid': False})
    
    user_data = auth_manager.validate_token(token)
    if user_data:
        return jsonify({'valid': True, 'user': user_data['user']})
    return jsonify({'valid': False})


@app.route('/api/auth/forgot-password', methods=['POST'])
@limiter.limit("3 per minute")
def forgot_password():
    """Request a password reset email"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'success': False, 'error': 'Email is required'}), 400
    
    # Get base URL for reset link
    base_url = request.host_url.rstrip('/')
    
    result = auth_manager.request_password_reset(email, base_url)
    return jsonify(result)


@app.route('/api/auth/verify-reset-token/<token>', methods=['GET'])
def verify_reset_token(token):
    """Verify a password reset token is valid"""
    result = auth_manager.verify_password_reset_token(token)
    return jsonify(result)


@app.route('/api/auth/reset-password', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password_with_token():
    """Reset password using a valid reset token"""
    data = request.get_json()
    token = data.get('token', '')
    new_password = data.get('new_password', '')
    
    if not token or not new_password:
        return jsonify({'success': False, 'error': 'Token and new password are required'}), 400
    
    # Enforce password policy
    pw_check = PasswordPolicy.validate(new_password)
    if not pw_check['valid']:
        return jsonify({'success': False, 'error': pw_check['errors'][0]}), 400
    
    result = auth_manager.reset_password_with_token(token, new_password)
    return jsonify(result)


@app.route('/reset-password')
def reset_password_page():
    """Render the password reset page"""
    return render_template('reset_password.html')


@app.route('/api/admin/emergency-reset', methods=['POST'])
@limiter.limit("3 per minute")
def emergency_password_reset():
    """Emergency password reset endpoint - requires ADMIN_SECRET_KEY env variable"""
    data = request.get_json()
    
    # Require the admin secret key from environment (never hardcoded)
    secret_key = data.get('secret_key', '')
    expected_key = Config.ADMIN_SECRET_KEY
    if not expected_key or secret_key != expected_key:
        logger.warning(f"Unauthorized emergency reset attempt from {_get_client_ip()}")
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    email = data.get('email', '').strip()
    new_password = data.get('new_password', '')
    
    if not email or not new_password:
        return jsonify({'success': False, 'error': 'Email and new_password required'}), 400
    
    result = auth_manager.reset_password_by_email(email, new_password)
    return jsonify(result)


@app.route('/api/admin/check-user', methods=['POST'])
@limiter.limit("5 per minute")
def check_user_exists():
    """Check if user exists in database - requires secret key"""
    data = request.get_json()
    
    secret_key = data.get('secret_key', '')
    expected_key = Config.ADMIN_SECRET_KEY
    if not expected_key or secret_key != expected_key:
        logger.warning(f"Unauthorized check-user attempt from {_get_client_ip()}")
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    email = data.get('email', '').strip()
    
    session = auth_manager.get_session()
    try:
        from auth import User
        user = session.query(User).filter(User.email == email).first()
        if user:
            return jsonify({
                'success': True,
                'found': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'has_password': bool(user.password_hash),
                    'is_active': user.is_active,
                    'created_at': str(user.created_at) if user.created_at else None
                }
            })
        else:
            return jsonify({
                'success': True,
                'found': False
            })
    finally:
        session.close()


@app.route('/api/admin/reset-admin-password', methods=['POST'])
@limiter.limit("3 per minute")
def reset_admin_password():
    """Reset admin/employee password - requires secret key"""
    data = request.get_json()
    
    secret_key = data.get('secret_key', '')
    expected_key = Config.ADMIN_SECRET_KEY
    if not expected_key or secret_key != expected_key:
        logger.warning(f"Unauthorized admin password reset attempt from {_get_client_ip()}")
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    username = data.get('username', '').strip()
    new_password = data.get('new_password', '')
    
    if not username or not new_password:
        return jsonify({'success': False, 'error': 'Username and new_password required'}), 400
    
    # Reset admin/employee password using bcrypt
    import bcrypt as _bcrypt
    from admin import Employee
    
    admin_session = admin_manager.get_session()
    try:
        employee = admin_session.query(Employee).filter(Employee.username == username).first()
        if not employee:
            return jsonify({'success': False, 'error': 'Employee not found'})
        
        hashed = _bcrypt.hashpw(new_password.encode('utf-8'), _bcrypt.gensalt(rounds=12))
        employee.salt = 'bcrypt'
        employee.password_hash = hashed.decode('utf-8')
        admin_session.commit()
        
        return jsonify({'success': True, 'message': 'Admin password reset successfully'})
    except Exception as e:
        admin_session.rollback()
        logger.error(f"Operation failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'})
    finally:
        admin_session.close()


@app.route('/api/admin/verify-all-users', methods=['POST'])
@limiter.limit("3 per minute")
def verify_all_users():
    """Mark all existing users as verified - requires secret key"""
    data = request.get_json()
    
    secret_key = data.get('secret_key', '')
    expected_key = Config.ADMIN_SECRET_KEY
    if not expected_key or secret_key != expected_key:
        logger.warning(f"Unauthorized verify-all-users attempt from {_get_client_ip()}")
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    try:
        from auth import User
        db_session = auth_manager.get_session()
        count = db_session.query(User).filter(User.is_verified == False).update({'is_verified': True})
        db_session.commit()
        db_session.close()
        return jsonify({'success': True, 'message': f'Verified {count} users'})
    except Exception as e:
        logger.error(f"Operation failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'})


# ============== Browser Extension API ==============

# Track daily scans per user (in-memory, resets on server restart)
# In production, use Redis or database
extension_scan_counts = {}

def get_scan_limit(subscription_tier):
    """Get daily scan limit based on subscription tier. -1 means unlimited."""
    limits = {
        'free': -1,
        'pro': -1,
        'enterprise': -1
    }
    return limits.get(subscription_tier, -1)

@app.route('/api/extension/auth', methods=['POST', 'OPTIONS'])
@cross_origin(origins='*', supports_credentials=False)
def extension_auth():
    """Authenticate user from browser extension"""
    data = request.get_json()
    
    email_or_username = data.get('email_or_username', '').strip()
    password = data.get('password', '')
    
    if not email_or_username or not password:
        return jsonify({'success': False, 'error': 'Credentials required'}), 400
    
    result = auth_manager.login(
        email_or_username,
        password,
        remember_me=True,
        device_info='SecureLink Browser Extension',
        ip_address=_get_client_ip()
    )
    
    if result.get('success'):
        # Return subscription info for extension
        user = result.get('user', {})
        return jsonify({
            'success': True,
            'token': result.get('token'),
            'user': {
                'id': user.get('id'),
                'email': user.get('email'),
                'username': user.get('username'),
                'subscription_tier': user.get('subscription_tier', 'free')
            },
            'scan_limit': get_scan_limit(user.get('subscription_tier', 'free'))
        })
    
    return jsonify(result)


@app.route('/api/extension/status', methods=['GET', 'OPTIONS'])
@cross_origin(origins='*', supports_credentials=False)
def extension_status():
    """Get extension status and remaining scans for authenticated user"""
    token = get_token_from_request()
    
    if not token:
        # Anonymous user - limited access (still encourages sign-up)
        return jsonify({
            'authenticated': False,
            'subscription_tier': 'anonymous',
            'scan_limit': 15,
            'scans_remaining': 15,
            'message': 'Sign in for 50 free scans per day'
        })
    
    user_data = auth_manager.validate_token(token)
    if not user_data:
        return jsonify({
            'authenticated': False,
            'subscription_tier': 'anonymous',
            'scan_limit': 15,
            'scans_remaining': 15,
            'message': 'Session expired. Please sign in again.'
        })
    
    user = user_data.get('user', {})
    user_id = user.get('id')
    tier = user.get('subscription_tier', 'free')
    limit = get_scan_limit(tier)
    
    # Get today's scan count
    from datetime import date
    today = date.today().isoformat()
    key = f"{user_id}:{today}"
    scans_today = extension_scan_counts.get(key, 0)
    
    remaining = max(0, limit - scans_today) if limit != -1 else 'unlimited'

    return jsonify({
        'authenticated': True,
        'user': {
            'email': user.get('email'),
            'username': user.get('username')
        },
        'subscription_tier': tier,
        'scan_limit': limit if limit != -1 else 'unlimited',
        'scans_today': scans_today,
        'scans_remaining': remaining
    })


@app.route('/api/extension/verify', methods=['POST', 'OPTIONS'])
@cross_origin(origins='*', supports_credentials=False)
def extension_verify():
    """Verify URL from extension with rate limiting based on subscription"""
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    # TEST MODE: Special test URLs for extension testing
    # These return fake high-risk scores without being blocked by Chrome
    test_urls = {
        'securelink-test-malware.com': {
            'risk_score': 0.95,
            'threats': ['Test Malware Site', 'Suspicious Domain Pattern'],
            'warnings': ['This is a test URL for extension development']
        },
        'test-phishing-example.net': {
            'risk_score': 0.85,
            'threats': ['Test Phishing Attempt'],
            'warnings': ['Fake login page detected (TEST)']
        },
        'fake-dangerous-site.xyz': {
            'risk_score': 0.75,
            'threats': ['Suspicious TLD', 'New Domain'],
            'warnings': ['Test warning message']
        }
    }
    
    # Check if this is a test URL
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        hostname_clean = hostname.replace('www.', '')
        
        if hostname_clean in test_urls:
            test_data = test_urls[hostname_clean]
            return jsonify({
                'url': url,
                'risk_score': test_data['risk_score'],
                'is_safe': False,
                'risk_level': 'high',
                'threats_detected': test_data['threats'],
                'warnings': test_data['warnings'],
                'subscription_tier': 'test',
                'scans_remaining': 999,
                'test_mode': True
            })
    except:
        pass
    
    # Check authentication
    token = get_token_from_request()
    user_id = None
    tier = 'anonymous'
    limit = 15  # Anonymous users get 15 scans, free registered users get 50
    
    if token:
        user_data = auth_manager.validate_token(token)
        if user_data:
            user = user_data.get('user', {})
            user_id = user.get('id')
            tier = user.get('subscription_tier', 'free')
            limit = get_scan_limit(tier)
    
    # Check rate limit
    from datetime import date
    today = date.today().isoformat()
    key = f"{user_id or _get_client_ip()}:{today}"
    scans_today = extension_scan_counts.get(key, 0)
    
    if limit != -1 and scans_today >= limit:
        upgrade_msg = "Upgrade to Pro for 500 scans/day" if tier == 'free' else "Sign in for more scans"
        return jsonify({
            'error': 'Daily scan limit reached',
            'limit_reached': True,
            'subscription_tier': tier,
            'message': upgrade_msg,
            'upgrade_url': 'https://securelinkapp.com/login'
        }), 429
    
    # Increment scan count
    extension_scan_counts[key] = scans_today + 1
    
    # Perform the actual verification
    result = verifier.verify_link(url)
    
    # Return result with subscription info
    response = {
        'url': url,
        'risk_score': result.risk_score,
        'is_safe': result.is_safe,
        'risk_level': result.risk_level.value if hasattr(result.risk_level, 'value') else str(result.risk_level),
        'threats_detected': result.threats_detected,
        'warnings': result.warnings,
        'subscription_tier': tier,
        'scans_remaining': max(0, limit - scans_today - 1) if limit != -1 else 'unlimited'
    }
    
    return jsonify(response)


@app.route('/api/auth/change-password', methods=['POST'])
@limiter.limit("5 per minute")
@require_auth
def change_password():
    """Change user password"""
    data = request.get_json()
    
    new_password = data.get('new_password', '')
    if new_password:
        pw_check = PasswordPolicy.validate(new_password)
        if not pw_check['valid']:
            return jsonify({'success': False, 'error': pw_check['errors'][0]}), 400
    
    result = auth_manager.change_password(
        request.current_user['id'],
        data.get('old_password', ''),
        new_password
    )
    
    return jsonify(result)


# ============== OAuth Routes ==============

@app.route('/api/auth/oauth/providers', methods=['GET'])
def get_oauth_providers():
    """Get list of configured OAuth providers"""
    providers = get_configured_providers()
    return jsonify({'providers': providers})


@app.route('/auth/oauth/<provider>')
def oauth_login(provider):
    """Start OAuth login flow"""
    client = get_oauth_client(provider)
    if not client:
        return redirect(f'/login?error=OAuth provider {provider} not configured')
    
    # Store the action (login or signup) in session
    session['oauth_action'] = request.args.get('action', 'login')
    
    redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
    return client.authorize_redirect(redirect_uri)


@app.route('/auth/oauth/<provider>/callback')
def oauth_callback(provider):
    """Handle OAuth callback"""
    client = get_oauth_client(provider)
    if not client:
        return redirect('/login?error=OAuth provider not configured')
    
    try:
        token = client.authorize_access_token()
        user_info = client.userinfo()
        
        parsed_info = parse_user_info(provider, user_info)
        email = parsed_info.get('email')
        
        if not email:
            return redirect('/login?error=Could not get email from provider')
        
        # Check if user exists with this OAuth provider
        existing_oauth_user = auth_manager.get_user_by_oauth(provider, parsed_info['provider_id'])
        
        if existing_oauth_user:
            # User exists with OAuth - log them in
            auth_token = auth_manager.create_session_for_oauth_user(
                existing_oauth_user['id'],
                user_agent=request.headers.get('User-Agent'),
                ip_address=_get_client_ip()
            )
            if auth_token:
                # Store token in server-side session (NOT in URL) for secure handoff
                session['oauth_auth_token'] = auth_token
                return redirect('/?oauth_complete=1')
            return redirect('/login?error=Failed to create session')
        
        # Check if user exists with this email
        existing_email_user = auth_manager.get_user_by_email_only(email)
        
        action = session.get('oauth_action', 'login')
        
        if existing_email_user:
            # User exists with email but no OAuth linked
            if existing_email_user.get('oauth_provider'):
                # Already linked to different provider
                return redirect(f'/login?error=Email already linked to {existing_email_user["oauth_provider"]}')
            
            # Link OAuth to existing account and log in
            auth_manager.link_oauth_to_user(
                existing_email_user['id'],
                provider,
                parsed_info['provider_id'],
                parsed_info.get('picture')
            )
            auth_token = auth_manager.create_session_for_oauth_user(
                existing_email_user['id'],
                user_agent=request.headers.get('User-Agent'),
                ip_address=_get_client_ip()
            )
            if auth_token:
                session['oauth_auth_token'] = auth_token
                return redirect('/?oauth_complete=1')
            return redirect('/login?error=Failed to create session')
        
        # No existing user - check if trying to login or signup
        if action == 'login':
            # Redirect to signup with pre-filled info
            session['oauth_pending'] = {
                'provider': provider,
                'provider_id': parsed_info['provider_id'],
                'email': email,
                'name': parsed_info.get('name'),
                'picture': parsed_info.get('picture')
            }
            return redirect('/login?tab=register&oauth=pending')
        
        # Create new user
        username = generate_username_from_email(email)
        result = auth_manager.create_oauth_user(
            email=email,
            username=username,
            provider=provider,
            provider_id=parsed_info['provider_id'],
            full_name=parsed_info.get('name'),
            avatar_url=parsed_info.get('picture')
        )
        
        if result['success']:
            auth_token = auth_manager.create_session_for_oauth_user(
                result['user']['id'],
                user_agent=request.headers.get('User-Agent'),
                ip_address=_get_client_ip()
            )
            if auth_token:
                session['oauth_auth_token'] = auth_token
                return redirect('/?oauth_complete=1&welcome=true')
        
        return redirect('/login?error=Failed to create account')
        
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        return redirect(f'/login?error=OAuth authentication failed')


@app.route('/api/auth/oauth/token', methods=['POST'])
def get_oauth_token():
    """Retrieve the auth token stored in the server-side session after OAuth callback.
    This avoids putting the token in URL query parameters."""
    auth_token = session.pop('oauth_auth_token', None)
    if auth_token:
        return jsonify({'success': True, 'token': auth_token})
    return jsonify({'success': False, 'error': 'No pending OAuth token'}), 400


@app.route('/api/auth/oauth/complete-signup', methods=['POST'])
def complete_oauth_signup():
    """Complete signup for pending OAuth user"""
    pending = session.get('oauth_pending')
    if not pending:
        return jsonify({'success': False, 'error': 'No pending OAuth signup'})
    
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'success': False, 'error': 'Username required'})
    
    result = auth_manager.create_oauth_user(
        email=pending['email'],
        username=username,
        provider=pending['provider'],
        provider_id=pending['provider_id'],
        full_name=pending.get('name'),
        avatar_url=pending.get('picture')
    )
    
    if result['success']:
        # Clear pending data
        session.pop('oauth_pending', None)
        
        auth_token = auth_manager.create_session_for_oauth_user(
            result['user']['id'],
            user_agent=request.headers.get('User-Agent'),
            ip_address=_get_client_ip()
        )
        if auth_token:
            return jsonify({
                'success': True,
                'token': auth_token,
                'user': result['user']
            })
    
    return jsonify(result)


@app.route('/api/auth/oauth/pending', methods=['GET'])
def get_pending_oauth():
    """Get pending OAuth signup data"""
    pending = session.get('oauth_pending')
    if pending:
        return jsonify({
            'pending': True,
            'email': pending['email'],
            'name': pending.get('name'),
            'provider': pending['provider']
        })
    return jsonify({'pending': False})


# ============== Profile Routes ==============

@app.route('/api/profile', methods=['GET'])
@require_auth
def get_profile():
    """Get current user profile"""
    return jsonify({
        'user': request.current_user,
        'plan_limits': request.plan_limits
    })


@app.route('/api/profile', methods=['PUT'])
@require_auth
def update_profile():
    """Update user profile"""
    data = request.get_json()
    result = auth_manager.update_profile(request.current_user['id'], data)
    return jsonify(result)


# ================================================================
#  License Key API — self-hosted instance management
# ================================================================

@app.route('/api/license/validate', methods=['POST'])
def validate_license_key():
    """
    Public endpoint called by self-hosted instances to validate their LICENSE_KEY.
    Returns the tier associated with the key.
    """
    import secrets as _secrets
    data = request.get_json(silent=True) or {}
    key = str(data.get('key', '')).strip()
    if not key:
        return jsonify({'error': 'No key provided'}), 400

    db_session = auth_manager.get_session()
    try:
        lk = db_session.query(LicenseKey).filter_by(key=key, is_active=True).first()
        if not lk:
            return jsonify({'error': 'Invalid or inactive license key'}), 403

        from datetime import datetime as _dt
        if lk.expires_at is not None and lk.expires_at < _dt.utcnow():
            return jsonify({'error': 'License key has expired'}), 403

        lk.last_validated = _dt.utcnow()
        db_session.commit()
        return jsonify({'valid': True, 'tier': lk.tier})
    finally:
        db_session.close()


@app.route('/api/license/keys', methods=['GET'])
@require_auth
def list_license_keys():
    """List all license keys for the authenticated user."""
    db_session = auth_manager.get_session()
    try:
        keys = db_session.query(LicenseKey).filter_by(
            user_id=request.current_user['id']
        ).order_by(LicenseKey.created_at.desc()).all()
        return jsonify({'keys': [k.to_dict() for k in keys]})
    finally:
        db_session.close()


@app.route('/api/license/keys', methods=['POST'])
@require_auth
def generate_license_key():
    """Generate a new license key (Pro and Enterprise only)."""
    import secrets as _secrets
    tier = request.current_user.get('subscription_tier', 'free')
    if tier == 'free':
        return jsonify({'error': 'License keys require a Pro or Enterprise subscription'}), 403
    if not _subscription_is_active(request.current_user):
        return jsonify({'error': 'Your subscription has expired. Please renew to generate license keys.'}), 403

    # Key limits per tier
    KEY_LIMITS = {'pro': 3, 'enterprise': None}  # None = unlimited
    limit = KEY_LIMITS.get(tier)

    data = request.get_json(silent=True) or {}
    label = str(data.get('label', 'My Instance'))[:100].strip() or 'My Instance'

    key = 'sl_' + _secrets.token_urlsafe(40)

    db_session = auth_manager.get_session()
    try:
        if limit is not None:
            existing = db_session.query(LicenseKey).filter_by(
                user_id=request.current_user['id'], is_active=True
            ).count()
            if existing >= limit:
                return jsonify({'error': f'Pro plan allows up to {limit} active license keys. Revoke an existing key to create a new one.'}), 403

        lk = LicenseKey(
            user_id=request.current_user['id'],
            key=key,
            tier=tier,
            label=label,
        )
        db_session.add(lk)
        db_session.commit()
        return jsonify({'key': lk.to_dict()}), 201
    finally:
        db_session.close()


@app.route('/api/license/keys/<int:key_id>', methods=['DELETE'])
@require_auth
def revoke_license_key(key_id):
    """Revoke (deactivate) a license key."""
    db_session = auth_manager.get_session()
    try:
        lk = db_session.query(LicenseKey).filter_by(
            id=key_id, user_id=request.current_user['id']
        ).first()
        if not lk:
            return jsonify({'error': 'Key not found'}), 404
        lk.is_active = False
        db_session.commit()
        return jsonify({'success': True})
    finally:
        db_session.close()


@app.route('/api/usage', methods=['GET'])
@require_auth
def get_usage():
    """Get user's scan usage for today"""
    result = auth_manager.check_scan_limit(request.current_user['id'])
    return jsonify(result)


@app.route('/api/tutorial-seen', methods=['POST'])
@require_auth
def mark_tutorial_seen():
    """Mark the tutorial as seen for the current user"""
    try:
        session = auth_manager.get_session()
        from auth import User
        user = session.query(User).filter_by(id=request.current_user['id']).first()
        if user:
            user.tutorial_seen = True
            session.commit()
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'User not found'}), 404
    except Exception as e:
        logger.error(f"Operation failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500
    finally:
        session.close()


# ============== Dark Web Monitoring Routes ==============

@app.route('/dark-web-monitor')
def dark_web_monitor_page():
    """Render the dark web monitoring page"""
    return render_template('dark_web_monitor.html')


@app.route('/api/dark-web/assets', methods=['GET'])
@require_pro
def get_dark_web_assets():
    """Get all monitored assets"""
    assets = auth_manager.get_monitored_assets(request.current_user['id'])
    count_info = auth_manager.get_monitored_asset_count(request.current_user['id'])
    return jsonify({'assets': assets, 'count': count_info})


@app.route('/api/dark-web/assets', methods=['POST'])
@require_pro
def add_dark_web_asset():
    """Add a new asset to dark web monitoring"""
    data = request.get_json()
    asset_type = data.get('asset_type', '').strip()
    asset_value = data.get('asset_value', '').strip()
    label = data.get('label', '').strip()
    
    if not asset_type or not asset_value:
        return jsonify({'success': False, 'error': 'Asset type and value are required'}), 400
    
    # Validate asset type
    valid_types = ['email', 'domain', 'username', 'phone']
    if asset_type not in valid_types:
        return jsonify({'success': False, 'error': f'Invalid asset type. Must be one of: {", ".join(valid_types)}'}), 400
    
    # Validate format
    if asset_type == 'email' and not dark_web_monitor.validate_email(asset_value):
        return jsonify({'success': False, 'error': 'Invalid email address format'}), 400
    if asset_type == 'domain' and not dark_web_monitor.validate_domain(asset_value):
        return jsonify({'success': False, 'error': 'Invalid domain format'}), 400
    
    result = auth_manager.add_monitored_asset(
        user_id=request.current_user['id'],
        asset_type=asset_type,
        asset_value=asset_value,
        label=label or None
    )
    return jsonify(result)


@app.route('/api/dark-web/assets/<int:asset_id>', methods=['DELETE'])
@require_pro
def delete_dark_web_asset(asset_id):
    """Remove a monitored asset"""
    result = auth_manager.delete_monitored_asset(request.current_user['id'], asset_id)
    return jsonify(result)


@app.route('/api/dark-web/scan', methods=['POST'])
@limiter.limit("10 per minute")
@require_pro
def scan_dark_web():
    """Run a dark web scan for a specific asset or all assets"""
    data = request.get_json() or {}
    user_id = request.current_user['id']
    asset_id = data.get('asset_id')
    
    try:
        assets = auth_manager.get_monitored_assets(user_id)
        if not assets:
            return jsonify({'error': 'No monitored assets. Add an email or domain to start monitoring.'}), 400
        
        # Filter to specific asset if requested
        if asset_id:
            assets = [a for a in assets if a['id'] == asset_id]
            if not assets:
                return jsonify({'error': 'Asset not found'}), 404
        
        all_results = []
        for asset in assets:
            if asset['asset_type'] == 'email':
                scan_result = dark_web_monitor.full_scan(asset['asset_value'])
                # Save results as alerts
                auth_manager.save_scan_results(user_id, asset['id'], scan_result)
                all_results.append({
                    'asset': asset,
                    'results': scan_result
                })
            elif asset['asset_type'] == 'domain':
                breaches, error = dark_web_monitor.check_domain_breaches(asset['asset_value'])
                scan_result = {
                    'breaches': [b.to_dict() for b in breaches],
                    'pastes': [],
                    'risk_level': 'safe' if not breaches else 'medium',
                    'errors': [error] if error else [],
                    'summary': {
                        'total_breaches': len(breaches),
                        'total_pastes': 0,
                        'total_records_exposed': sum(b.pwn_count for b in breaches)
                    }
                }
                auth_manager.save_scan_results(user_id, asset['id'], scan_result)
                all_results.append({
                    'asset': asset,
                    'results': scan_result
                })
        
        return jsonify({
            'success': True,
            'results': all_results,
            'assets_scanned': len(all_results)
        })
    except Exception as e:
        logger.error(f"Dark web scan error: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500


@app.route('/api/dark-web/scan-quick', methods=['POST'])
@limiter.limit("10 per minute")
@require_auth
def quick_dark_web_scan():
    """Quick one-off scan without saving as monitored asset (available to all users)"""
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({'error': 'Email address is required'}), 400
    if not dark_web_monitor.validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    try:
        result = dark_web_monitor.full_scan(email)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Quick dark web scan error: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500


@app.route('/api/dark-web/alerts', methods=['GET'])
@require_pro
def get_dark_web_alerts():
    """Get dark web alerts for the user"""
    unread_only = request.args.get('unread', 'false').lower() == 'true'
    limit = min(int(request.args.get('limit', 50)), 200)
    alerts = auth_manager.get_dark_web_alerts(request.current_user['id'], unread_only=unread_only, limit=limit)
    counts = auth_manager.get_dark_web_alert_count(request.current_user['id'])
    return jsonify({'alerts': alerts, 'counts': counts})


@app.route('/api/dark-web/alerts/<int:alert_id>/read', methods=['POST'])
@require_pro
def mark_dark_web_alert_read(alert_id):
    """Mark alert as read"""
    result = auth_manager.mark_alert_read(request.current_user['id'], alert_id)
    return jsonify(result)


@app.route('/api/dark-web/alerts/read-all', methods=['POST'])
@require_pro
def mark_all_dark_web_alerts_read():
    """Mark all alerts as read"""
    result = auth_manager.mark_all_alerts_read(request.current_user['id'])
    return jsonify(result)


@app.route('/api/dark-web/alerts/<int:alert_id>/resolve', methods=['POST'])
@require_pro
def resolve_dark_web_alert(alert_id):
    """Mark alert as resolved"""
    result = auth_manager.resolve_alert(request.current_user['id'], alert_id)
    return jsonify(result)


@app.route('/api/dark-web/password-check', methods=['POST'])
@limiter.limit("10 per minute")
@require_pro
def check_password_dark_web():
    """Check if a password has appeared in data breaches (Pro and Enterprise only)"""
    data = request.get_json() or {}
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    count, error = dark_web_monitor.check_password_pwned(password)
    if error:
        return jsonify({'error': error}), 500
    return jsonify({'count': count, 'is_compromised': count > 0})


# ============== Subscription Routes ==============

@app.route('/api/subscription/plans', methods=['GET'])
def get_plans():
    """Get available subscription plans"""
    return jsonify(SUBSCRIPTION_PLANS)


@app.route('/api/subscription/upgrade', methods=['POST'])
@require_auth
def upgrade_subscription():
    """Change subscription tier (handles both upgrades in demo mode and downgrades)"""
    data = request.get_json()
    plan = data.get('plan', 'pro')
    
    current_tier = request.current_user.get('subscription_tier', 'free')
    plan_order = {'free': 0, 'pro': 1, 'team': 2, 'enterprise': 3}
    is_downgrade = plan_order.get(plan, 0) < plan_order.get(current_tier, 0)
    
    # Always allow downgrades (free)
    if is_downgrade:
        expires_at = None if plan == 'free' else datetime.utcnow() + timedelta(days=30)
        
        result = auth_manager.update_subscription(
            request.current_user['id'],
            plan,
            expires_at
        )
        
        return jsonify(result)
    
    # If Stripe is not configured, allow demo upgrades
    if not payment_manager.is_configured():
        # Demo mode - upgrade instantly
        expires_at = datetime.utcnow() + timedelta(days=30)
        
        result = auth_manager.update_subscription(
            request.current_user['id'],
            plan,
            expires_at
        )
        
        return jsonify(result)
    
    # With Stripe configured, upgrades should use payment checkout flow
    return jsonify({'error': 'Please use the payment checkout flow'}), 400


# ============== Payment Routes ==============

@app.route('/api/payments/config', methods=['GET'])
def get_payment_config():
    """Get payment configuration for frontend"""
    return jsonify({
        'publishable_key': payment_manager.get_publishable_key(),
        'is_configured': payment_manager.is_configured(),
        'prices': payment_manager.get_plan_prices()
    })


@app.route('/api/payments/create-checkout-session', methods=['POST'])
@require_auth
def create_checkout_session():
    """Create a Stripe Checkout session for subscription payment"""
    data = request.get_json()
    plan = data.get('plan', 'pro')
    billing_period = data.get('billing_period', 'monthly')
    
    if plan not in ['pro', 'team', 'enterprise']:
        return jsonify({'error': 'Invalid plan'}), 400
    
    if billing_period not in ['monthly', 'yearly']:
        return jsonify({'error': 'Invalid billing period'}), 400
    
    user = request.current_user
    
    # Get or create Stripe customer ID
    customer_id = user.get('stripe_customer_id')
    if not customer_id:
        customer_id = payment_manager.create_customer(
            email=user['email'],
            name=user.get('full_name') or user['username'],
            metadata={'user_id': user['id']}
        )
        # Save customer ID to user (would need to add this to auth.py)
        if customer_id and not customer_id.startswith('demo_'):
            auth_manager.update_stripe_customer_id(user['id'], customer_id)
    
    # Create checkout session
    base_url = request.host_url.rstrip('/')
    session = payment_manager.create_checkout_session(
        customer_id=customer_id,
        plan=plan,
        billing_period=billing_period,
        success_url=f"{base_url}/profile?payment=success&plan={plan}",
        cancel_url=f"{base_url}/profile?payment=cancelled",
        user_id=user['id']
    )
    
    if not session:
        return jsonify({'error': 'Failed to create checkout session'}), 500
    
    # If demo mode, instantly upgrade
    if session.get('demo_mode'):
        expires_at = datetime.utcnow() + timedelta(days=30)
        result = auth_manager.update_subscription(user['id'], plan, expires_at)
        return jsonify({
            'demo_mode': True,
            'success': True,
            **result
        })
    
    return jsonify({
        'session_id': session['session_id'],
        'url': session['url']
    })


@app.route('/api/payments/verify', methods=['POST'])
@require_auth
def verify_payment():
    """Verify a checkout session and activate the subscription"""
    data = request.get_json()
    session_id = data.get('session_id')

    if not session_id:
        return jsonify({'error': 'Missing session_id'}), 400

    user = request.current_user

    # Verify the checkout session with Stripe and get plan from Stripe metadata (not client)
    result = payment_manager.verify_checkout_session(session_id)

    if result and result.get('success'):
        # Use plan from Stripe session metadata — never trust the client-supplied plan
        plan = result.get('plan')
        if plan not in ['pro', 'team', 'enterprise']:
            logger.error(f"verify_payment: invalid plan '{plan}' in Stripe session {session_id}")
            return jsonify({'error': 'Invalid plan in session metadata'}), 400

        expires_at = datetime.utcnow() + timedelta(days=30)
        update_result = auth_manager.update_subscription(user['id'], plan, expires_at)

        if result.get('subscription_id'):
            auth_manager.update_stripe_subscription_id(user['id'], result['subscription_id'])

        logger.info(f"Activated {plan} subscription for user {user['id']} via checkout verification")
        return jsonify({
            'success': True,
            **update_result
        })

    return jsonify({'error': 'Payment not completed or session invalid'}), 400


@app.route('/api/payments/manage', methods=['POST'])
@require_auth
def manage_subscription():
    """Create a Stripe Customer Portal session for subscription management"""
    user = request.current_user
    customer_id = user.get('stripe_customer_id')
    
    if not customer_id:
        return jsonify({'error': 'No active subscription found'}), 400
    
    base_url = request.host_url.rstrip('/')
    session = payment_manager.create_portal_session(
        customer_id=customer_id,
        return_url=f"{base_url}/profile"
    )
    
    if not session:
        return jsonify({'error': 'Failed to create portal session'}), 500
    
    return jsonify({'url': session['url']})


@app.route('/api/payments/cancel', methods=['POST'])
@require_auth
def cancel_subscription():
    """Cancel the current subscription"""
    user = request.current_user
    subscription_id = user.get('stripe_subscription_id')
    
    if not subscription_id:
        # Demo mode - just downgrade to free
        result = auth_manager.update_subscription(user['id'], 'free', None)
        return jsonify(result)
    
    # Cancel subscription with Stripe
    success = payment_manager.cancel_subscription(subscription_id, at_period_end=False)
    
    if success:
        # Immediately downgrade to free
        result = auth_manager.update_subscription(user['id'], 'free', None)
        return jsonify({
            **result,
            'message': 'Subscription cancelled successfully. You are now on the Free plan.'
        })
    
    return jsonify({'error': 'Failed to cancel subscription'}), 500


@app.route('/api/webhooks/stripe', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhook events"""
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    event = payment_manager.handle_webhook(payload, sig_header)
    
    if not event:
        return jsonify({'error': 'Invalid webhook'}), 400
    
    event_type = event['type']
    data = event['data']
    
    try:
        if event_type == 'checkout.session.completed':
            metadata       = data.get('metadata', {})
            payment_type   = metadata.get('type')
            subscription_id = data.get('subscription')

            if payment_type == 'team_seats':
                # ---- Org named-user seat plan purchased ----
                org_id_meta   = metadata.get('org_id')
                tier          = metadata.get('tier', 'enterprise')
                seat_count    = int(metadata.get('seat_count', 1))
                billing_period = metadata.get('billing_period', 'monthly')
                purchased_by  = metadata.get('user_id')
                customer_id   = data.get('customer')

                if billing_period == 'yearly':
                    expires_at = datetime.utcnow() + timedelta(days=365)
                else:
                    expires_at = datetime.utcnow() + timedelta(days=30)

                if org_id_meta:
                    plan = db.create_org_license_plan(
                        org_id=int(org_id_meta),
                        tier=tier,
                        seat_count=seat_count,
                        purchased_by=int(purchased_by) if purchased_by else None,
                        billing_period=billing_period,
                        stripe_subscription_id=subscription_id,
                        stripe_customer_id=customer_id,
                        expires_at=expires_at,
                    )
                    # Auto-assign a seat to the purchaser
                    if purchased_by:
                        buyer = auth_manager.get_user_by_id(int(purchased_by))
                        if buyer:
                            db.assign_org_seat(
                                plan_id=plan['id'],
                                org_id=int(org_id_meta),
                                email=buyer['email'],
                                assigned_by=int(purchased_by),
                                tier=tier,
                            )
                    logger.info(f"Org {org_id_meta}: created {seat_count}-seat {tier} plan (sub {subscription_id})")
            else:
                # ---- Individual subscription purchased ----
                user_id = metadata.get('user_id')
                plan    = metadata.get('plan')
                if user_id and plan:
                    expires_at = datetime.utcnow() + timedelta(days=30)
                    auth_manager.update_subscription(user_id, plan, expires_at)
                    if subscription_id:
                        auth_manager.update_stripe_subscription_id(user_id, subscription_id)
                    logger.info(f"Activated {plan} subscription for user {user_id}")

        elif event_type == 'invoice.paid':
            # Recurring payment successful
            subscription_id = data.get('subscription')
            if subscription_id:
                # Check if this is an org team plan renewal
                org_plan = db.get_org_license_plan_by_stripe(subscription_id)
                if org_plan:
                    billing_period = org_plan.get('billing_period', 'monthly')
                    if billing_period == 'yearly':
                        new_expires = datetime.utcnow() + timedelta(days=365)
                    else:
                        new_expires = datetime.utcnow() + timedelta(days=30)
                    db.update_org_license_plan_seats(org_plan['organization_id'], org_plan['seat_count'])
                    logger.info(f"Renewed org team plan {org_plan['id']} (sub {subscription_id})")
                else:
                    user = auth_manager.get_user_by_subscription_id(subscription_id)
                    if user:
                        new_expires = datetime.utcnow() + timedelta(days=30)
                        auth_manager.update_subscription(user['id'], user['subscription_tier'], new_expires)
                        logger.info(f"Extended subscription for user {user['id']} (sub {subscription_id})")
                    else:
                        logger.warning(f"invoice.paid: no user found for subscription {subscription_id}")

        elif event_type == 'customer.subscription.deleted':
            subscription_id = data.get('id')
            if subscription_id:
                # Check if this is an org team plan
                org_plan = db.get_org_license_plan_by_stripe(subscription_id)
                if org_plan:
                    db.expire_org_license_plan(subscription_id)
                    logger.info(f"Expired org team plan for sub {subscription_id}")
                else:
                    user = auth_manager.get_user_by_subscription_id(subscription_id)
                    if user:
                        auth_manager.update_subscription(user['id'], 'free', None)
                        logger.info(f"Downgraded user {user['id']} to free (sub {subscription_id} deleted)")
                    else:
                        logger.warning(f"subscription.deleted: no user found for subscription {subscription_id}")
        
        elif event_type == 'invoice.payment_failed':
            # Payment failed - notify user
            customer_email = data.get('customer_email')
            logger.warning(f"Payment failed for {customer_email}")
    
    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
    
    return jsonify({'received': True})


# ============== Link Verification Routes ==============

# Anonymous quota tracking is DB-backed via Database.check_and_increment_anon_quota()


@app.route('/api/public/breach-check', methods=['POST'])
@limiter.limit("5 per minute")
def public_breach_check():
    """Public email breach check — returns count/risk only, no breach names."""
    import re
    import uuid as _uuid

    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip().lower()
    if not email or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({'error': 'A valid email address is required'}), 400

    anon_id = request.cookies.get('sl_anon_id')
    new_anon_id = None
    if not anon_id:
        anon_id = str(_uuid.uuid4())
        new_anon_id = anon_id

    remaining = db.get_anon_quota_remaining(anon_id, 'bc', 3)
    if remaining <= 0:
        return jsonify({
            'error': 'Daily limit reached',
            'message': 'Create a free account to check more emails.',
            'checks_remaining': 0,
            'limit_reached': True
        }), 429

    # Check API key before burning a user's daily check
    if not getattr(dark_web_monitor, 'hibp_api_key', None):
        return jsonify({'error': 'Breach database not configured. Check back soon.'}), 503

    try:
        breaches, error = dark_web_monitor.check_email_breaches(email)
    except Exception as e:
        logger.error(f"Public breach check error: {e}")
        return jsonify({'error': 'Breach database temporarily unavailable'}), 503

    if error:
        return jsonify({'error': error}), 503

    # Increment only after a successful API call
    db.check_and_increment_anon_quota(anon_id, 'bc', 3)
    remaining_after = max(0, remaining - 1)

    breach_count = len(breaches)
    if breach_count == 0:
        risk_level = 'none'
    elif breach_count <= 2:
        risk_level = 'low'
    elif breach_count <= 5:
        risk_level = 'medium'
    else:
        risk_level = 'high'

    resp = jsonify({
        'has_breaches': breach_count > 0,
        'breach_count': breach_count,
        'risk_level': risk_level,
        'checks_remaining': remaining_after,
        'is_public': True
    })
    if new_anon_id:
        resp.set_cookie('sl_anon_id', new_anon_id, max_age=365*24*3600, httponly=True, samesite='Lax')
    return resp


@app.route('/api/scan-status', methods=['GET'])
def get_scan_status():
    """Get current scan count for anonymous users"""
    limit = 15
    anon_id = request.cookies.get('sl_anon_id', '')
    remaining = db.get_anon_quota_remaining(anon_id, 'lnk', limit) if anon_id else limit
    return jsonify({
        'scans_today': limit - remaining,
        'limit': limit,
        'remaining': remaining
    })

@app.route('/api/verify', methods=['POST'])
def verify_link():
    """API endpoint to verify a single link"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Check auth for scan limits
    token = get_token_from_request()
    user_id = None
    is_anonymous = True
    
    if token:
        user_data = auth_manager.validate_token(token)
        if user_data:
            user_id = user_data['user']['id']
            is_anonymous = False
            
            # Check scan limit for authenticated users
            limit_check = auth_manager.check_scan_limit(user_id)
            if not limit_check.get('allowed'):
                return jsonify({
                    'error': 'Daily scan limit reached',
                    'limit': limit_check.get('limit'),
                    'used': limit_check.get('used'),
                    'upgrade_url': '/pricing'
                }), 429
    
    # Rate limit for anonymous users (15 scans/day per browser cookie)
    import uuid as _uuid
    new_anon_id = None
    if is_anonymous:
        anon_id = request.cookies.get('sl_anon_id')
        if not anon_id:
            anon_id = str(_uuid.uuid4())
            new_anon_id = anon_id
        if not db.check_and_increment_anon_quota(anon_id, 'lnk', 15):
            return jsonify({
                'error': 'Daily scan limit reached',
                'message': 'Create a free account to get 25 scans per day!',
                'limit': 15,
                'signup_url': '/login'
            }), 429

    try:
        # Verify the link
        result = verifier.verify_link(url)

        # Save to database with user_id if authenticated
        db.save_verification(result, source='manual', user_id=user_id)
        
        # Increment scan count if authenticated
        if user_id:
            auth_manager.increment_scan_count(user_id)
        
        # Send notification if unsafe
        if not result.is_safe:
            notification_service.notify(result)
        
        resp = jsonify(result.to_dict())
        if new_anon_id:
            resp.set_cookie('sl_anon_id', new_anon_id, max_age=365*24*3600, httponly=True, samesite='Lax')
        return resp

    except Exception as e:
        logger.error(f"Error verifying link: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500


@app.route('/api/health-check-quota', methods=['GET'])
def health_check_quota():
    limit = 3
    anon_id = request.cookies.get('sl_anon_id', '')
    remaining = db.get_anon_quota_remaining(anon_id, 'hc', limit) if anon_id else limit
    return jsonify({'remaining': remaining, 'limit': limit})


@app.route('/api/health-check', methods=['POST'])
def domain_health_check():
    """Domain health check — authenticated users get unlimited checks; anonymous limited to 3/day."""
    import re
    import uuid as _uuid
    data = request.get_json() or {}
    domain = data.get('domain', '').strip().lower()
    domain = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    if not domain or '.' not in domain:
        return jsonify({'error': 'Please enter a valid domain name'}), 400

    # Authenticated users bypass the quota
    token = get_token_from_request()
    is_authenticated = False
    if token:
        user_data = auth_manager.validate_token(token)
        if user_data:
            is_authenticated = True

    new_anon_id = None
    if not is_authenticated:
        anon_id = request.cookies.get('sl_anon_id')
        if not anon_id:
            anon_id = str(_uuid.uuid4())
            new_anon_id = anon_id
        if not db.check_and_increment_anon_quota(anon_id, 'hc', 3):
            return jsonify({
                'error': 'Daily limit reached. Create a free account for more checks.',
                'limit_reached': True
            }), 429

    try:
        result = _domain_scanner.scan_domain(domain)
        r = result.to_dict()
        ssl = r.get('ssl_info', {})
        dns = r.get('dns_info', {})
        headers = r.get('headers_info', {})
        findings = r.get('findings', [])
        resp = jsonify({
            'domain': r.get('domain', domain),
            'score': r.get('score', 0),
            'grade': r.get('grade', 'F'),
            'ssl': {
                'valid': ssl.get('valid'),
                'issuer': ssl.get('issuer'),
                'days_remaining': ssl.get('days_remaining'),
                'protocol': ssl.get('protocol'),
            },
            'dns': {
                'has_spf': dns.get('has_spf'),
                'has_dmarc': dns.get('has_dmarc'),
                'has_dnssec': dns.get('has_dnssec'),
            },
            'headers': {
                'missing': headers.get('headers_missing', []),
            },
            'findings_count': {
                'critical': len([f for f in findings if f.get('severity') == 'critical']),
                'high':     len([f for f in findings if f.get('severity') == 'high']),
                'medium':   len([f for f in findings if f.get('severity') == 'medium']),
            },
            'scan_duration_ms': r.get('scan_duration_ms'),
        })
        if new_anon_id:
            resp.set_cookie('sl_anon_id', new_anon_id, max_age=365*24*3600, httponly=True, samesite='Lax')
        return resp
    except Exception as e:
        logger.error(f"Health check error for {domain}: {e}", exc_info=True)
        return jsonify({'error': 'Unable to scan domain. Please try again.'}), 500


@app.route('/api/reports/health-check-pdf', methods=['POST'])
@require_auth
def health_check_pdf():
    """Export domain health check as PDF (Pro+)."""
    import re as _re
    from io import BytesIO
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

    user = request.current_user
    tier = user.get('subscription_tier', 'free')
    if tier not in ('pro', 'team', 'enterprise'):
        return jsonify({'error': 'PDF export requires a Pro plan'}), 403

    data = request.get_json() or {}
    domain = data.get('domain', '').strip().lower()
    domain = _re.sub(r'^https?://', '', domain).split('/')[0].strip()
    if not domain or '.' not in domain:
        return jsonify({'error': 'Please provide a valid domain'}), 400

    try:
        result = _domain_scanner.scan_domain(domain)
        r = result.to_dict()
    except Exception as e:
        logger.error(f"Health check PDF scan error: {e}", exc_info=True)
        return jsonify({'error': 'Unable to scan domain'}), 500

    ssl_info     = r.get('ssl_info', {})
    dns_info     = r.get('dns_info', {})
    headers_info = r.get('headers_info', {})
    findings     = r.get('findings', [])
    score        = r.get('score', 0)
    grade        = r.get('grade', 'F')
    generated_at = datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')

    grade_colors = {'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
                    'C': '#f59e0b', 'D': '#f97316', 'F': '#ef4444'}
    grade_hex = grade_colors.get(grade, '#94a3b8')

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)

    styles = getSampleStyleSheet()
    brand_blue = colors.HexColor('#0d6efd')
    dark       = colors.HexColor('#1a1a2e')
    muted_c    = colors.HexColor('#6c757d')
    success_c  = colors.HexColor('#198754')
    danger_c   = colors.HexColor('#dc3545')
    warning_c  = colors.HexColor('#f59e0b')

    h1      = ParagraphStyle('h1',    parent=styles['Normal'], fontSize=22, textColor=brand_blue, spaceAfter=4, fontName='Helvetica-Bold')
    h2      = ParagraphStyle('h2',    parent=styles['Normal'], fontSize=12, textColor=dark, spaceAfter=6, spaceBefore=14, fontName='Helvetica-Bold')
    body    = ParagraphStyle('body',  parent=styles['Normal'], fontSize=10, textColor=dark, leading=14)
    small   = ParagraphStyle('small', parent=styles['Normal'], fontSize=9,  textColor=muted_c, leading=12)

    BASE_STYLE = [
        ('BACKGROUND',    (0, 0), (-1, 0), brand_blue),
        ('TEXTCOLOR',     (0, 0), (-1, 0), colors.white),
        ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 10),
        ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 10),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [colors.HexColor('#f8f9fa'), colors.white]),
        ('GRID',          (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
    ]

    # Score interpretation
    if score >= 90:
        interpretation = 'Excellent — Strong security posture'
    elif score >= 80:
        interpretation = 'Good — Minor improvements recommended'
    elif score >= 70:
        interpretation = 'Fair — Several issues need attention'
    elif score >= 60:
        interpretation = 'Poor — Significant security gaps present'
    else:
        interpretation = 'Critical — Immediate action required'

    story = []

    # ── Header ────────────────────────────────────────────────────────────
    story.append(Paragraph(
        f'<font color="#0d6efd"><b>SecureLink</b></font>  '
        f'<font size=10 color="#6c757d">Domain Health Report</font>', h1))
    story.append(Spacer(1, 2))
    story.append(Paragraph(f'<b>{domain}</b>', ParagraphStyle('domain', parent=styles['Normal'],
        fontSize=14, textColor=dark, spaceAfter=3, fontName='Helvetica-Bold')))
    story.append(Paragraph(
        f'Generated {generated_at} &nbsp;&bull;&nbsp; {tier.title()} Plan',
        ParagraphStyle('meta', parent=styles['Normal'], fontSize=9, textColor=muted_c, spaceAfter=8)))
    story.append(HRFlowable(width='100%', thickness=2, color=brand_blue, spaceAfter=16))

    # ── Score + Grade block ───────────────────────────────────────────────
    grade_color_rl = colors.HexColor(grade_hex)
    score_block = Table([[
        Paragraph(f'<font size=36 color="{grade_hex}"><b>{score}</b></font>'
                  f'<font size=11 color="#6c757d"> / 100</font>', body),
        Table([[
            Paragraph(f'<font size=22 color="{grade_hex}"><b>{grade}</b></font>', body),
        ]], colWidths=[0.6*inch], rowHeights=[0.45*inch],
            style=[('BOX', (0,0), (-1,-1), 1.5, grade_color_rl),
                   ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                   ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                   ('TOPPADDING', (0,0), (-1,-1), 4),
                   ('BOTTOMPADDING', (0,0), (-1,-1), 4)]),
        Paragraph(f'<i>{interpretation}</i>',
                  ParagraphStyle('interp', parent=styles['Normal'],
                                 fontSize=10, textColor=muted_c, leading=14)),
    ]], colWidths=[1.5*inch, 0.8*inch, None])
    score_block.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (0,0), 0),
        ('LEFTPADDING', (1,0), (1,0), 10),
        ('LEFTPADDING', (2,0), (2,0), 16),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('TOPPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(score_block)
    story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#dee2e6'), spaceAfter=12))

    # ── Security Checks ───────────────────────────────────────────────────
    story.append(Paragraph('Security Checks', h2))
    missing_hdrs = headers_info.get('headers_missing', [])
    days_msg = f' ({ssl_info.get("days_remaining")}d remaining)' if ssl_info.get('days_remaining') is not None else ''

    details_data = [
        ['Check', 'Result', 'Details'],
        ['SSL Certificate',
         '✓  PASS' if ssl_info.get('valid') else '✗  FAIL',
         f"Valid{days_msg} — Issuer: {ssl_info.get('issuer','Unknown')}" if ssl_info.get('valid') else 'Invalid or missing'],
        ['SPF Record',
         '✓  PASS' if dns_info.get('has_spf') else '✗  FAIL',
         'Configured' if dns_info.get('has_spf') else 'Missing — email spoofing risk'],
        ['DMARC Record',
         '✓  PASS' if dns_info.get('has_dmarc') else '⚠  WARN',
         'Configured' if dns_info.get('has_dmarc') else 'Missing — phishing risk'],
        ['Security Headers',
         '✓  PASS' if not missing_hdrs else '⚠  WARN',
         'All present' if not missing_hdrs
         else f"{len(missing_hdrs)} missing: {', '.join(missing_hdrs[:3])}{'…' if len(missing_hdrs)>3 else ''}"],
    ]
    det_style = TableStyle(BASE_STYLE + [
        ('FONTNAME', (1, 1), (1, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (1, 1), (1, -1), success_c),
        ('COLWIDTH',  (0, 0), (0, -1), 1.6*inch),
    ])
    for i, row in enumerate(details_data[1:], 1):
        status = row[1]
        if 'FAIL' in status:
            det_style.add('TEXTCOLOR', (1, i), (1, i), danger_c)
        elif 'WARN' in status:
            det_style.add('TEXTCOLOR', (1, i), (1, i), warning_c)
    det_tbl = Table(details_data, colWidths=[1.6*inch, 0.9*inch, None])
    det_tbl.setStyle(det_style)
    story.append(det_tbl)

    # ── Findings ──────────────────────────────────────────────────────────
    crit = len([f for f in findings if f.get('severity') == 'critical'])
    high = len([f for f in findings if f.get('severity') == 'high'])
    med  = len([f for f in findings if f.get('severity') == 'medium'])
    story.append(Paragraph('Findings', h2))
    if crit == 0 and high == 0 and med == 0:
        story.append(Paragraph(
            '✓  No critical, high, or medium findings — domain is well-configured.',
            ParagraphStyle('ok', parent=styles['Normal'], fontSize=10,
                           textColor=success_c, leading=14, spaceAfter=8)))
    else:
        findings_rows = [['Severity', 'Count']]
        if crit > 0:
            findings_rows.append(['Critical', str(crit)])
        if high > 0:
            findings_rows.append(['High', str(high)])
        if med > 0:
            findings_rows.append(['Medium', str(med)])
        fi_style = TableStyle(BASE_STYLE)
        row_idx = 1
        if crit > 0:
            fi_style.add('TEXTCOLOR', (1, row_idx), (1, row_idx), danger_c)
            fi_style.add('FONTNAME',  (1, row_idx), (1, row_idx), 'Helvetica-Bold')
            row_idx += 1
        if high > 0:
            fi_style.add('TEXTCOLOR', (1, row_idx), (1, row_idx), warning_c)
            fi_style.add('FONTNAME',  (1, row_idx), (1, row_idx), 'Helvetica-Bold')
            row_idx += 1
        fi_tbl = Table(findings_rows, colWidths=[2*inch, 1*inch])
        fi_tbl.setStyle(fi_style)
        story.append(fi_tbl)

    # ── Footer ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 24))
    story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#dee2e6'), spaceAfter=10))
    cta_style = ParagraphStyle('cta', parent=styles['Normal'], fontSize=9,
                               textColor=muted_c, leading=13, spaceAfter=4)
    story.append(Paragraph(
        'Want 24/7 monitoring? <b>Upgrade to Enterprise</b> for continuous attack surface scanning, '
        'IDS alerts, DNS/SSL change detection, and daily PDF reports. '
        '<font color="#0d6efd">securelinkapp.com</font>', cta_style))
    story.append(Paragraph(
        f'CONFIDENTIAL &nbsp;&bull;&nbsp; Generated by SecureLink &nbsp;&bull;&nbsp; {generated_at}',
        ParagraphStyle('conf', parent=styles['Normal'], fontSize=8,
                       textColor=colors.HexColor('#adb5bd'), leading=11)))

    doc.build(story)
    buffer.seek(0)
    filename = f"securelink-health-{domain}-{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return send_file(buffer, mimetype='application/pdf',
                     as_attachment=True, download_name=filename)


@app.route('/api/health-check/watch', methods=['POST'])
@require_auth
def add_health_watch():
    """Add a domain to a Pro user's watch list for score-drop alerts."""
    user = request.current_user
    tier = user.get('subscription_tier', 'free')
    if tier not in ('pro', 'team', 'enterprise'):
        return jsonify({'error': 'Domain watch alerts require a Pro plan'}), 403

    import re as _re
    data = request.get_json() or {}
    domain = data.get('domain', '').strip().lower()
    domain = _re.sub(r'^https?://', '', domain).split('/')[0].strip()
    if not domain or '.' not in domain:
        return jsonify({'error': 'Please provide a valid domain'}), 400

    user_id = user['id']
    watches = db.get_health_watches(user_id)
    if len(watches) >= 10 and not any(w['domain'] == domain for w in watches):
        return jsonify({'error': 'Watch limit reached (10 domains). Remove one to add another.'}), 429

    db.add_health_watch(user_id, domain)
    return jsonify({'success': True, 'domain': domain})


@app.route('/api/health-check/watch/<path:domain>', methods=['DELETE'])
@require_auth
def remove_health_watch(domain):
    """Remove a domain from a Pro user's watch list."""
    user = request.current_user
    tier = user.get('subscription_tier', 'free')
    if tier not in ('pro', 'team', 'enterprise'):
        return jsonify({'error': 'Domain watch alerts require a Pro plan'}), 403
    db.remove_health_watch(user['id'], domain)
    return jsonify({'success': True})


@app.route('/api/health-check/watches', methods=['GET'])
@require_auth
def list_health_watches():
    """List all watched domains for the current Pro user."""
    user = request.current_user
    tier = user.get('subscription_tier', 'free')
    if tier not in ('pro', 'team', 'enterprise'):
        return jsonify({'error': 'Domain watch alerts require a Pro plan'}), 403
    return jsonify({'watches': db.get_health_watches(user['id'])})


@app.route('/api/scan-file', methods=['POST'])
@limiter.limit("10 per minute")
@require_auth
def scan_file():
    """API endpoint to scan a file for security threats (all authenticated tiers)"""
    import re
    import hashlib

    user = request.current_user
    user_id = user.get('id')
    tier = user.get('subscription_tier', 'free')

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Enforce tier-based file size limits
    tier_size_limits = {
        'free':       25  * 1024 * 1024,   # 25 MB
        'pro':        50  * 1024 * 1024,   # 50 MB
        'enterprise': 200 * 1024 * 1024,   # 200 MB
    }
    max_size = tier_size_limits.get(tier, 25 * 1024 * 1024)

    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)

    if file_size > max_size:
        limit_mb = max_size // (1024 * 1024)
        return jsonify({'error': f'File size exceeds the {limit_mb}MB limit for your plan'}), 400

    # Get file extension
    filename = file.filename.lower()
    extension = '.' + filename.split('.')[-1] if '.' in filename else ''

    allowed_extensions = ['.txt', '.html', '.htm', '.js', '.css', '.json', '.xml', '.csv', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.eml', '.msg']
    if extension not in allowed_extensions:
        return jsonify({'error': 'File type not supported'}), 400

    # Check scan limits
    limit_check = auth_manager.check_scan_limit(user_id)
    if not limit_check.get('allowed'):
        return jsonify({
            'error': 'Daily scan limit reached',
            'limit': limit_check.get('limit'),
            'used': limit_check.get('used')
        }), 429
    
    try:
        # Read file content
        content = file.read()
        file_hash = hashlib.sha256(content).hexdigest()
        
        threats = []
        warnings = []
        info = []
        
        # Try to decode as text for text-based files
        text_content = None
        text_extensions = ['.txt', '.html', '.htm', '.js', '.css', '.json', '.xml', '.csv', '.eml', '.msg']
        
        if extension in text_extensions:
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except:
                try:
                    text_content = content.decode('latin-1', errors='ignore')
                except:
                    pass
        
        # Analyze text content for suspicious patterns
        if text_content:
            # Check for malicious URLs
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            urls = re.findall(url_pattern, text_content, re.IGNORECASE)
            
            suspicious_url_patterns = [
                r'bit\.ly', r'tinyurl', r'goo\.gl', r't\.co',
                r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$', r'\.gq$',
                r'login|signin|account|secure|verify|update|confirm',
                r'paypal|bank|amazon|microsoft|apple|google',
            ]
            
            for url in urls[:50]:  # Limit URL checks
                for pattern in suspicious_url_patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        warnings.append(f"Suspicious URL found: {url[:100]}...")
                        break
            
            # Check for script injection patterns
            script_patterns = [
                (r'<script[^>]*>.*?</script>', 'Embedded JavaScript detected'),
                (r'javascript:', 'JavaScript protocol handler detected'),
                (r'on\w+\s*=\s*["\']', 'Inline event handlers detected'),
                (r'eval\s*\(', 'Potentially dangerous eval() function'),
                (r'document\.write', 'document.write() detected'),
                (r'innerHTML\s*=', 'innerHTML manipulation detected'),
                (r'\.exec\s*\(', 'exec() function detected'),
                (r'fromCharCode', 'Character code conversion (possible obfuscation)'),
                (r'atob\s*\(|btoa\s*\(', 'Base64 encoding/decoding detected'),
                (r'\\x[0-9a-f]{2}|\\u[0-9a-f]{4}', 'Encoded characters detected'),
            ]
            
            for pattern, description in script_patterns:
                if re.search(pattern, text_content, re.IGNORECASE | re.DOTALL):
                    if extension in ['.js', '.html', '.htm']:
                        info.append(description)
                    else:
                        warnings.append(description)
            
            # Check for phishing indicators
            phishing_patterns = [
                (r'password', 'Password field or reference detected'),
                (r'credit.?card|cvv|expir', 'Credit card information reference'),
                (r'social.?security|ssn', 'Social Security Number reference'),
                (r'urgent|immediate.?action|act.?now', 'Urgency language detected'),
                (r'account.?suspend|verify.?account|unusual.?activity', 'Account verification scam language'),
                (r'wire.?transfer|bitcoin|cryptocurrency', 'Financial transfer reference'),
            ]
            
            for pattern, description in phishing_patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    warnings.append(description)
            
            # Check for malware indicators
            malware_patterns = [
                (r'powershell|cmd\.exe|bash', 'Shell command reference detected', True),
                (r'wget|curl\s+.*http', 'File download command detected', True),
                (r'\\\\[^\\]+\\[^\\]+', 'Network path (UNC) detected', False),
                (r'HKEY_|RegWrite|Registry', 'Windows Registry reference', True),
                (r'CreateObject|WScript', 'Windows Script Host reference', True),
                (r'ActiveXObject', 'ActiveX object reference detected', True),
                (r'\.exe|\.dll|\.bat|\.cmd|\.ps1|\.vbs', 'Executable file reference', False),
            ]
            
            for pattern, description, is_threat in malware_patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    if is_threat:
                        threats.append(description)
                    else:
                        warnings.append(description)
            
            # Check for macro indicators (Office files represented as XML)
            if extension in ['.xml', '.html']:
                macro_patterns = [
                    (r'vbaProject|macroEnabled', 'VBA macro reference detected'),
                    (r'AutoOpen|AutoExec|Document_Open', 'Auto-execute macro detected'),
                ]
                for pattern, description in macro_patterns:
                    if re.search(pattern, text_content, re.IGNORECASE):
                        threats.append(description)
        
        # Binary file analysis for Office documents
        if extension in ['.doc', '.docx', '.xls', '.xlsx', '.pdf']:
            # Check for embedded objects
            if b'OLE' in content or b'Root Entry' in content:
                warnings.append('OLE objects detected (may contain embedded content)')
            
            if b'/JavaScript' in content or b'/JS' in content:
                threats.append('JavaScript embedded in document')
            
            if b'/Launch' in content or b'/EmbeddedFile' in content:
                warnings.append('Embedded files or launch actions detected')
            
            if b'auto' in content.lower() and b'macro' in content.lower():
                warnings.append('Possible auto-executing macros detected')
        
        # Add file info
        info.append(f"File type: {extension.upper()}")
        info.append(f"File size: {file_size:,} bytes")
        info.append(f"SHA-256: {file_hash[:16]}...")
        
        # Determine risk level
        threats_count = len(threats)
        warnings_count = len(warnings)
        
        if threats_count > 0:
            risk_level = 'high' if threats_count > 2 else 'critical' if threats_count > 4 else 'high'
        elif warnings_count > 3:
            risk_level = 'medium'
        elif warnings_count > 0:
            risk_level = 'low'
        else:
            risk_level = 'safe'
        
        # Increment scan count if authenticated
        if user_id:
            auth_manager.increment_scan_count(user_id)
        
        logger.info(f"File scanned: {filename}, Risk: {risk_level}, Threats: {threats_count}, Warnings: {warnings_count}")
        
        return jsonify({
            'filename': file.filename,
            'file_size': file_size,
            'file_hash': file_hash,
            'risk_level': risk_level,
            'threats_count': threats_count + warnings_count,
            'threats': threats,
            'warnings': warnings,
            'info': info
        })
        
    except Exception as e:
        logger.error(f"Error scanning file: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500


@app.route('/api/history', methods=['GET'])
def get_history():
    """Get verification history for the current user"""
    limit = request.args.get('limit', 50, type=int)
    try:
        # Check if user is authenticated
        token = get_token_from_request()
        if token:
            user_data = auth_manager.validate_token(token)
            if user_data:
                user = user_data['user']
                user_id = user['id']
                
                # Get user's email accounts
                email_accounts = []
                try:
                    from auth import EmailAccount
                    session = auth_manager.get_session()
                    accounts = session.query(EmailAccount).filter(
                        EmailAccount.user_id == user_id
                    ).all()
                    email_accounts = [acc.email for acc in accounts]
                    session.close()
                except Exception as e:
                    logger.warning(f"Could not get email accounts: {e}")
                
                # Get only this user's verifications
                history = db.get_user_verifications(user_id, email_accounts, limit)
                return jsonify(history)
        
        # If not authenticated, return empty list (no anonymous history)
        return jsonify([])
    except Exception as e:
        logger.error(f"Error getting history: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get verification statistics for the current user"""
    try:
        user_id = getattr(request, 'current_user', {}).get('id') if hasattr(request, 'current_user') else None
        # Try to resolve user from token if not already set
        if user_id is None:
            token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
            if token:
                user_data = auth_manager.validate_token(token)
                if user_data:
                    user_id = user_data.get('id')
        stats = db.get_statistics(user_id=user_id)
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500


# ============== Cyber News Routes ==============

@app.route('/api/news', methods=['GET'])
def get_news():
    """Get latest cybersecurity news from RSS feeds"""
    try:
        max_articles = request.args.get('limit', 10, type=int)
        max_articles = min(max_articles, 20)  # Cap at 20 articles
        
        result = get_cyber_news(max_articles=max_articles)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error fetching news: {e}")
        return jsonify({'error': 'Failed to fetch news'}), 500


# ============== Dark Web Monitoring Status Route ==============

@app.route('/api/dark-web/status', methods=['GET'])
@require_auth
def get_dark_web_status():
    """Get dark web monitoring status for the navbar indicator"""
    user_id = request.current_user['id']
    tier = request.current_user.get('subscription_tier', 'free')
    
    if tier == 'free':
        return jsonify({
            'enabled': False,
            'asset_count': 0,
            'unread_alerts': 0,
            'critical_alerts': 0
        })
    
    try:
        assets = auth_manager.get_monitored_assets(user_id)
        alert_counts = auth_manager.get_dark_web_alert_count(user_id)
        
        return jsonify({
            'enabled': len(assets) > 0,
            'asset_count': len(assets),
            'unread_alerts': alert_counts.get('unread', 0),
            'critical_alerts': alert_counts.get('critical', 0)
        })
    except Exception as e:
        logger.error(f"Error getting dark web status: {e}")
        return jsonify({'enabled': False, 'asset_count': 0, 'unread_alerts': 0, 'critical_alerts': 0})


@app.route('/api/whitelist', methods=['GET', 'POST'])
@require_pro
def manage_whitelist():
    """Manage whitelisted domains"""
    if request.method == 'GET':
        return jsonify(db.get_whitelist())
    
    data = request.get_json()
    domain = data.get('domain', '').strip()
    notes = data.get('notes', '')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    success = db.add_to_whitelist(domain, notes)
    return jsonify({'success': success})


@app.route('/api/blacklist', methods=['GET', 'POST'])
@require_pro
def manage_blacklist():
    """Manage blacklisted domains"""
    if request.method == 'GET':
        return jsonify(db.get_blacklist())
    
    data = request.get_json()
    domain = data.get('domain', '').strip()
    reason = data.get('reason', '')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    success = db.add_to_blacklist(domain, reason)
    return jsonify({'success': success})


@app.route('/api/lookup/<path:url>', methods=['GET'])
def lookup_url(url):
    """Look up previous verification for a URL"""
    result = db.get_verification_by_url(url)
    if result:
        return jsonify(result)
    return jsonify({'error': 'URL not found in history'}), 404


# ==================== Weekly Reports API ====================

@app.route('/api/reports/weekly-stats', methods=['GET'])
@require_auth
def get_weekly_stats():
    """Get weekly security statistics for the current user"""
    user_id = request.current_user.get('id')
    days = request.args.get('days', 7, type=int)
    
    stats = report_generator.get_user_weekly_stats(user_id, days)
    return jsonify(stats)


@app.route('/api/reports/send-test', methods=['POST'])
@require_auth
def send_test_report():
    """Send a test weekly report to the current user"""
    user = request.current_user
    
    success = report_generator.send_report({
        'id': user.get('id'),
        'email': user.get('email'),
        'username': user.get('username')
    })
    
    if success:
        return jsonify({'success': True, 'message': 'Test report sent to your email'})
    return jsonify({'success': False, 'error': 'Failed to send report. Check SMTP settings.'}), 500


@app.route('/api/reports/send-hourly-test', methods=['POST'])
@require_auth
def send_test_hourly_report():
    """Send a test hourly threat report to the current user"""
    user = request.current_user
    
    # Get recent flagged emails (last 24 hours for testing, not just last hour)
    from datetime import timedelta
    session = report_generator.db.Session()
    try:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        flagged = session.query(VerificationRecord).filter(
            and_(
                VerificationRecord.user_id == user.get('id'),
                VerificationRecord.source == 'email',
                VerificationRecord.is_safe == False,
                VerificationRecord.created_at >= start_time
            )
        ).order_by(VerificationRecord.created_at.desc()).limit(10).all()
        
        flagged_emails = [record.to_dict() for record in flagged]
    finally:
        session.close()
    
    if not flagged_emails:
        return jsonify({
            'success': False, 
            'error': 'No flagged emails in the last 24 hours. The hourly report only sends when threats are detected.'
        })
    
    # Generate and send the report
    try:
        html_content = report_generator.generate_hourly_report_html(user, flagged_emails)
        text_content = report_generator.generate_hourly_report_text(user, flagged_emails)
        
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        import smtplib
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 SecureLink Alert (TEST): {len(flagged_emails)} Threat(s) - {datetime.now().strftime('%I:%M %p')}"
        msg['From'] = config.SMTP_USERNAME or config.EMAIL_USERNAME
        msg['To'] = user.get('email')
        
        msg.attach(MIMEText(text_content, 'plain'))
        msg.attach(MIMEText(html_content, 'html'))
        
        smtp_host = config.SMTP_HOST or 'smtp.gmail.com'
        smtp_port = config.SMTP_PORT or 587
        smtp_user = config.SMTP_USERNAME or config.EMAIL_USERNAME
        smtp_pass = config.SMTP_PASSWORD or config.EMAIL_PASSWORD
        
        if not smtp_user or not smtp_pass:
            return jsonify({'success': False, 'error': 'SMTP not configured. Set SMTP_USERNAME and SMTP_PASSWORD.'}), 500
        
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        
        return jsonify({
            'success': True, 
            'message': f'Test hourly report sent with {len(flagged_emails)} flagged email(s)'
        })
        
    except Exception as e:
        logger.error(f"Failed to send test hourly report: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@app.route('/api/reports/preferences', methods=['PUT'])
@require_auth
def update_report_preferences():
    """Update weekly report preferences"""
    data = request.get_json()
    user_id = request.current_user.get('id')
    
    result = auth_manager.update_profile(user_id, {
        'weekly_reports_enabled': data.get('weekly_reports_enabled', True)
    })
    
    return jsonify(result)


@app.route('/api/reports/security-report-pdf')
@require_auth
def generate_security_report_pdf():
    """Generate and download a PDF security posture report (Enterprise only)."""
    from io import BytesIO
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from attack_surface_db import AttackSurfaceDB

    user = request.current_user
    if user.get('subscription_tier') not in ('team', 'enterprise'):
        return jsonify({'error': 'PDF reports require a Team or Enterprise plan'}), 403

    user_id = user['id']
    user_name = user.get('display_name') or user.get('username') or user['email'].split('@')[0]
    user_email = user['email']
    generated_at = datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')

    # Gather data
    stats = report_generator.get_user_weekly_stats(user_id, days=30)
    as_db = AttackSurfaceDB(config)
    domains = as_db.get_user_domains(user_id)
    dw_assets = auth_manager.get_monitored_assets(user_id)
    dw_counts = auth_manager.get_dark_web_alert_count(user_id)

    # ── Build PDF ──
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                            topMargin=0.75 * inch, bottomMargin=0.75 * inch)

    styles = getSampleStyleSheet()
    brand_blue = colors.HexColor('#0d6efd')
    dark       = colors.HexColor('#1a1a2e')
    muted      = colors.HexColor('#6c757d')
    danger     = colors.HexColor('#dc3545')
    success    = colors.HexColor('#198754')
    warning    = colors.HexColor('#ffc107')

    h1 = ParagraphStyle('h1', parent=styles['Normal'], fontSize=24, textColor=brand_blue,
                         spaceAfter=4, fontName='Helvetica-Bold')
    h2 = ParagraphStyle('h2', parent=styles['Normal'], fontSize=13, textColor=dark,
                         spaceAfter=6, spaceBefore=14, fontName='Helvetica-Bold')
    body = ParagraphStyle('body', parent=styles['Normal'], fontSize=10, textColor=dark, leading=14)
    muted_style = ParagraphStyle('muted', parent=styles['Normal'], fontSize=9, textColor=muted, leading=12)

    BASE_STYLE = [
        ('BACKGROUND',    (0, 0), (-1, 0), brand_blue),
        ('TEXTCOLOR',     (0, 0), (-1, 0), colors.white),
        ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 10),
        ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 10),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [colors.HexColor('#f8f9fa'), colors.white]),
        ('GRID',          (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
    ]

    def two_col_table(data, extra_cmds=None):
        """Build a standard two-column info table."""
        t = Table(data, colWidths=[3.5 * inch, 3.5 * inch])
        t.setStyle(TableStyle(BASE_STYLE + (extra_cmds or [])))
        return t

    story = []

    # ── Header ──
    story.append(Paragraph('SecureLink', h1))
    story.append(Paragraph('Security Posture Report',
                            ParagraphStyle('sub', parent=styles['Normal'], fontSize=16,
                                           textColor=dark, fontName='Helvetica-Bold', spaceAfter=2)))
    story.append(Paragraph(f'Prepared for: <b>{user_name}</b> ({user_email})', body))
    story.append(Paragraph(f'Generated: {generated_at} &nbsp;|&nbsp; Period: Last 30 days', muted_style))
    story.append(Paragraph('Plan: <b>Enterprise</b>', muted_style))
    story.append(HRFlowable(width='100%', thickness=1.5, color=brand_blue, spaceAfter=12, spaceBefore=8))

    # ── Security Summary ──
    summary    = stats.get('summary', {})
    risk       = stats.get('overall_risk', {})
    total      = summary.get('total_scans', 0)
    safe       = summary.get('safe_count', 0)
    unsafe     = summary.get('unsafe_count', 0)
    safe_pct   = summary.get('safe_percentage', 0)
    risk_level = risk.get('level', 'unknown').upper()

    risk_color_map = {
        'CRITICAL': danger,
        'HIGH':     colors.HexColor('#fd7e14'),
        'MEDIUM':   warning,
        'LOW':      colors.HexColor('#20c997'),
        'SAFE':     success,
        'UNKNOWN':  muted,
    }
    rl_color = risk_color_map.get(risk_level, muted)

    story.append(Paragraph('Security Summary', h2))
    story.append(two_col_table(
        [
            ['Metric',               'Value'],
            ['Total Scans (30 days)', str(total)],
            ['Safe Links',           f'{safe} ({safe_pct:.1f}%)'],
            ['Threats Detected',     str(unsafe)],
            ['Overall Risk Level',   risk_level],
        ],
        extra_cmds=[
            ('TEXTCOLOR', (1, 4), (1, 4), rl_color),
            ('FONTNAME',  (1, 4), (1, 4), 'Helvetica-Bold'),
        ]
    ))

    # ── Risk Breakdown ──
    story.append(Paragraph('Risk Breakdown', h2))
    rb = stats.get('risk_breakdown', {})
    rb_entries = [
        (colors.HexColor('#dc3545'), 'Critical'),
        (colors.HexColor('#fd7e14'), 'High'),
        (colors.HexColor('#ffc107'), 'Medium'),
        (colors.HexColor('#20c997'), 'Low'),
        (colors.HexColor('#198754'), 'Safe'),
    ]
    rb_data = [['Risk Level', 'Count']] + [
        [label, str(rb.get(label.lower(), 0))] for _, label in rb_entries
    ]
    rb_extra = []
    for i, (c, _) in enumerate(rb_entries):
        rb_extra += [
            ('TEXTCOLOR', (0, i + 1), (0, i + 1), c),
            ('FONTNAME',  (0, i + 1), (0, i + 1), 'Helvetica-Bold'),
        ]
    story.append(two_col_table(rb_data, extra_cmds=rb_extra))

    # ── Recent Threats ──
    story.append(Paragraph('Recent Threats Detected', h2))
    threats = stats.get('recent_threats', [])
    if threats:
        t_data = [['URL', 'Risk', 'Source', 'Detected']]
        small = ParagraphStyle('sm', fontSize=8, leading=10)
        for t in threats:
            detected = ''
            if t.get('detected_at'):
                try:
                    detected = datetime.fromisoformat(t['detected_at']).strftime('%Y-%m-%d')
                except Exception:
                    detected = str(t['detected_at'])[:10]
            t_data.append([
                Paragraph(t.get('url', '')[:70], small),
                t.get('risk_level', '').upper(),
                t.get('source', ''),
                detected,
            ])
        t_table = Table(t_data, colWidths=[3.0 * inch, 1.0 * inch, 0.9 * inch, 1.1 * inch])
        t_table.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, 0), brand_blue),
            ('TEXTCOLOR',     (0, 0), (-1, 0), colors.white),
            ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0, 0), (-1, -1), 9),
            ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING',   (0, 0), (-1, -1), 8),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
            ('TOPPADDING',    (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS',(0, 1), (-1, -1), [colors.HexColor('#f8f9fa'), colors.white]),
            ('GRID',          (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ]))
        story.append(t_table)
    else:
        story.append(Paragraph('No high or critical threats detected in the past 30 days.', body))

    # ── Dark Web Monitoring ──
    story.append(Paragraph('Dark Web Monitoring', h2))
    dw_email_count    = len([a for a in dw_assets if a.get('asset_type') == 'email'])
    dw_total_breaches = dw_counts.get('total', 0) if isinstance(dw_counts, dict) else 0
    dw_unread         = dw_counts.get('unread', 0) if isinstance(dw_counts, dict) else 0
    story.append(two_col_table([
        ['Metric',                    'Value'],
        ['Monitored Email Addresses', str(dw_email_count)],
        ['Total Breach Alerts',       str(dw_total_breaches)],
        ['Unread Alerts',             str(dw_unread)],
    ]))

    # ── Attack Surface Overview ──
    story.append(Paragraph('Attack Surface Overview', h2))
    scores    = [d.get('latest_score') for d in domains if d.get('latest_score') is not None]
    avg_score = f'{round(sum(scores) / len(scores), 1)}/100' if scores else 'N/A'
    grades    = [d.get('latest_grade', '') for d in domains if d.get('latest_grade')]
    story.append(two_col_table([
        ['Metric',                 'Value'],
        ['Monitored Domains',      str(len(domains))],
        ['Average Security Score', avg_score],
        ['Domains Graded D or F',  str(sum(1 for g in grades if g in ('D', 'F')))],
    ]))

    # ── Footer ──
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width='100%', thickness=0.5, color=muted, spaceBefore=8))
    story.append(Paragraph(
        'This report is confidential and intended solely for the named recipient. '
        'Generated by <b>SecureLink</b> &mdash; securelinkapp.com',
        ParagraphStyle('footer', parent=styles['Normal'], fontSize=8,
                       textColor=muted, alignment=1, spaceBefore=6)
    ))

    doc.build(story)
    buffer.seek(0)
    filename = f'securelink-report-{datetime.utcnow().strftime("%Y%m%d")}.pdf'
    return send_file(buffer, mimetype='application/pdf',
                     as_attachment=True, download_name=filename)


# ==================== Admin Panel Routes ====================

@app.route('/admin/login')
def admin_login_page():
    """Admin login page"""
    return render_template('admin/login.html')


@app.route('/admin/dashboard')
def admin_dashboard_page():
    """Admin dashboard page"""
    return render_template('admin/dashboard.html')


@app.route('/admin/tickets')
def admin_tickets_page():
    """Admin tickets list page"""
    return render_template('admin/tickets.html')


@app.route('/admin/tickets/<int:ticket_id>')
def admin_ticket_detail_page(ticket_id):
    """Admin ticket detail page"""
    return render_template('admin/ticket_detail.html')


@app.route('/admin/employees')
def admin_employees_page():
    """Admin employees management page"""
    return render_template('admin/employees.html')


@app.route('/admin/customers')
def admin_customers_page():
    """Admin customers management page"""
    return render_template('admin/customers.html')


@app.route('/admin/onboarding')
def admin_onboarding_page():
    """Employee onboarding request form"""
    return render_template('admin/onboarding.html')


@app.route('/admin/onboarding/requests')
def admin_onboarding_requests_page():
    """Admin page to view and manage onboarding requests"""
    return render_template('admin/onboarding_requests.html')


@app.route('/admin/database')
def admin_database_page():
    """Admin database monitoring page"""
    return render_template('admin/database.html')


@app.route('/admin/licenses')
def admin_licenses_page():
    """Admin license key management page"""
    return render_template('admin/licenses.html')


# ==================== Admin API Routes ====================

@app.route('/admin/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def admin_api_login():
    """Admin employee login"""
    data = request.get_json()
    email_or_username = data.get('email') or data.get('username')
    password = data.get('password')
    
    if not email_or_username or not password:
        return jsonify({'success': False, 'error': 'Email/username and password required'}), 400
    
    # Check account lockout
    lockout_key = f'admin:{email_or_username.lower()}'
    if lockout_manager.is_locked(lockout_key):
        remaining = lockout_manager.get_remaining_lockout(lockout_key)
        return jsonify({
            'success': False,
            'error': f'Account temporarily locked. Try again in {remaining // 60 + 1} minutes.',
            'locked': True
        }), 429
    
    result = admin_manager.login_employee(
        email_or_username, 
        password,
        device_info=request.headers.get('User-Agent'),
        ip_address=_get_client_ip()
    )
    
    if not result.get('success'):
        lockout_manager.record_failure(lockout_key)
    else:
        lockout_manager.clear(lockout_key)
    
    if result['success']:
        return jsonify(result)
    return jsonify(result), 401


@app.route('/admin/api/logout', methods=['POST'])
def admin_api_logout():
    """Admin employee logout"""
    token = get_token_from_request()
    if token:
        admin_manager.logout_employee(token)
    return jsonify({'success': True})


@app.route('/admin/api/validate', methods=['GET'])
def admin_api_validate():
    """Validate admin token"""
    token = get_token_from_request()
    if not token:
        return jsonify({'valid': False}), 401
    
    result = admin_manager.validate_employee_token(token)
    if result:
        return jsonify({'valid': True, 'employee': result['employee']})
    return jsonify({'valid': False}), 401


@app.route('/admin/api/employees', methods=['GET', 'POST'])
@require_admin_role('manager')
def admin_api_employees():
    """Get all employees or create new employee"""
    if request.method == 'GET':
        employees = admin_manager.get_all_employees()
        return jsonify(employees)
    
    # Create new employee
    data = request.get_json()
    result = admin_manager.create_employee(
        email=data.get('email'),
        username=data.get('username'),
        password=data.get('password'),
        full_name=data.get('full_name'),
        role=data.get('role', 'support'),
        phone=data.get('phone')
    )
    
    if result['success']:
        return jsonify(result)
    return jsonify(result), 400


@app.route('/admin/api/employees/<int:employee_id>', methods=['GET', 'PUT', 'DELETE'])
@require_admin_role('manager')
def admin_api_employee(employee_id):
    """Get, update or delete an employee"""
    if request.method == 'GET':
        employees = admin_manager.get_all_employees()
        employee = next((e for e in employees if e['id'] == employee_id), None)
        if employee:
            return jsonify(employee)
        return jsonify({'error': 'Employee not found'}), 404
    
    if request.method == 'PUT':
        data = request.get_json()
        result = admin_manager.update_employee(employee_id, data)
        if result['success']:
            return jsonify(result)
        return jsonify(result), 400
    
    if request.method == 'DELETE':
        # Prevent self-deletion
        if employee_id == request.current_employee.get('id'):
            return jsonify({'error': 'Cannot delete yourself'}), 400
        
        result = admin_manager.delete_employee(employee_id)
        if result['success']:
            return jsonify(result)
        return jsonify(result), 400


@app.route('/admin/api/tickets', methods=['GET'])
@require_admin
def admin_api_tickets():
    """Get all tickets with filtering"""
    result = admin_manager.get_tickets(
        status=request.args.get('status'),
        priority=request.args.get('priority'),
        category=request.args.get('category'),
        assigned_to_id=request.args.get('assigned_to_id', type=int),
        search=request.args.get('search'),
        page=request.args.get('page', 1, type=int),
        per_page=request.args.get('per_page', 20, type=int)
    )
    return jsonify(result)


@app.route('/admin/api/tickets/stats', methods=['GET'])
@require_admin
def admin_api_ticket_stats():
    """Get ticket statistics"""
    stats = admin_manager.get_ticket_stats()
    return jsonify(stats)


@app.route('/admin/api/tickets/<int:ticket_id>', methods=['GET', 'PUT'])
@require_admin
def admin_api_ticket(ticket_id):
    """Get or update a ticket"""
    if request.method == 'GET':
        ticket = admin_manager.get_ticket(ticket_id=ticket_id)
        if ticket:
            return jsonify(ticket)
        return jsonify({'error': 'Ticket not found'}), 404
    
    if request.method == 'PUT':
        data = request.get_json()
        result = admin_manager.update_ticket(ticket_id, data)
        if result['success']:
            return jsonify(result)
        return jsonify(result), 400


@app.route('/admin/api/tickets/<int:ticket_id>/respond', methods=['POST'])
@require_admin
def admin_api_ticket_respond(ticket_id):
    """Add a response to a ticket"""
    data = request.get_json()
    message = data.get('message', '').strip()
    is_internal = data.get('is_internal_note', False)
    resolve = data.get('resolve', False)
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    
    result = admin_manager.add_ticket_response(
        ticket_id=ticket_id,
        message=message,
        employee_id=request.current_employee.get('id'),
        is_internal_note=is_internal
    )
    
    if result['success'] and resolve:
        admin_manager.update_ticket(ticket_id, {'status': 'resolved'})
    
    if result['success']:
        return jsonify(result)
    return jsonify(result), 400


@app.route('/admin/api/customers', methods=['GET'])
@require_admin
def admin_api_customers():
    """Get all customers"""
    result = admin_manager.get_customers(
        search=request.args.get('search'),
        page=request.args.get('page', 1, type=int),
        per_page=request.args.get('per_page', 20, type=int)
    )
    return jsonify(result)


@app.route('/admin/api/customers/<int:user_id>', methods=['DELETE'])
@require_admin_role('manager')
def admin_api_delete_customer(user_id):
    """Delete a customer account (manager only)"""
    # First get the user to check for subscription
    user_data = auth_manager.get_user_by_id(user_id)
    if user_data:
        subscription_id = user_data.get('stripe_subscription_id')
        if subscription_id and not subscription_id.startswith('demo_'):
            try:
                payment_manager.cancel_subscription(subscription_id, at_period_end=False)
            except Exception as e:
                print(f"Warning: Failed to cancel subscription {subscription_id}: {e}")
    
    result = auth_manager.delete_user(user_id)
    return jsonify(result) if result['success'] else (jsonify(result), 400)


@app.route('/admin/api/customers/by-email', methods=['DELETE'])
@require_admin_role('manager')
def admin_api_delete_customer_by_email():
    """Delete a customer account by email (manager only)"""
    data = request.get_json()
    email = data.get('email', '').strip()
    if not email:
        return jsonify({'success': False, 'error': 'Email is required'}), 400
    
    # First get the user to check for subscription
    user_data = auth_manager.get_user_by_email(email)
    if user_data:
        subscription_id = user_data.get('stripe_subscription_id')
        if subscription_id and not subscription_id.startswith('demo_'):
            try:
                payment_manager.cancel_subscription(subscription_id, at_period_end=False)
            except Exception as e:
                print(f"Warning: Failed to cancel subscription {subscription_id}: {e}")
    
    result = auth_manager.delete_user_by_email(email)
    return jsonify(result) if result['success'] else (jsonify(result), 400)


# ==================== Admin License Key API ====================

@app.route('/admin/api/licenses', methods=['GET'])
@require_admin
def admin_api_licenses():
    """List all license keys with optional filters."""
    tier_filter  = request.args.get('tier')      # 'pro' | 'enterprise'
    status_filter = request.args.get('status')   # 'active' | 'revoked'
    search       = request.args.get('search', '').strip()
    page         = request.args.get('page', 1, type=int)
    per_page     = min(request.args.get('per_page', 25, type=int), 100)

    db_session = auth_manager.get_session()
    try:
        from auth import LicenseKey as _LK, User as _User
        q = db_session.query(_LK).join(_User, _LK.user_id == _User.id)
        if tier_filter:
            q = q.filter(_LK.tier == tier_filter)
        if status_filter == 'active':
            q = q.filter(_LK.is_active == True)
        elif status_filter == 'revoked':
            q = q.filter(_LK.is_active == False)
        if search:
            like = f'%{search}%'
            q = q.filter(
                (_LK.label.ilike(like)) |
                (_User.email.ilike(like)) |
                (_User.username.ilike(like))
            )
        total = q.count()
        keys  = q.order_by(_LK.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

        rows = []
        for lk in keys:
            d = lk.to_dict()
            d['owner_email']    = lk.user.email if lk.user else '?'
            d['owner_username'] = lk.user.username if lk.user else '?'
            rows.append(d)

        # Summary stats
        total_all    = db_session.query(_LK).count()
        active_all   = db_session.query(_LK).filter_by(is_active=True).count()
        pro_all      = db_session.query(_LK).filter_by(tier='pro',        is_active=True).count()
        ent_all      = db_session.query(_LK).filter_by(tier='enterprise', is_active=True).count()

        return jsonify({
            'keys':  rows,
            'total': total,
            'page':  page,
            'per_page': per_page,
            'stats': {
                'total':      total_all,
                'active':     active_all,
                'revoked':    total_all - active_all,
                'pro':        pro_all,
                'enterprise': ent_all,
            }
        })
    finally:
        db_session.close()


@app.route('/admin/api/licenses/<int:key_id>/revoke', methods=['POST'])
@require_admin
def admin_api_revoke_license(key_id):
    """Revoke any license key."""
    db_session = auth_manager.get_session()
    try:
        from auth import LicenseKey as _LK
        lk = db_session.query(_LK).filter_by(id=key_id).first()
        if not lk:
            return jsonify({'error': 'Key not found'}), 404
        lk.is_active = False
        db_session.commit()
        return jsonify({'success': True})
    finally:
        db_session.close()


@app.route('/admin/api/licenses/<int:key_id>/reinstate', methods=['POST'])
@require_admin
def admin_api_reinstate_license(key_id):
    """Re-activate a previously revoked key."""
    db_session = auth_manager.get_session()
    try:
        from auth import LicenseKey as _LK
        lk = db_session.query(_LK).filter_by(id=key_id).first()
        if not lk:
            return jsonify({'error': 'Key not found'}), 404
        lk.is_active = True
        db_session.commit()
        return jsonify({'success': True})
    finally:
        db_session.close()


@app.route('/admin/api/licenses/<int:key_id>/expiry', methods=['PUT'])
@require_admin
def admin_api_set_license_expiry(key_id):
    """Set or clear the expiry date on a license key."""
    from datetime import datetime as _dt
    data = request.get_json(silent=True) or {}
    db_session = auth_manager.get_session()
    try:
        from auth import LicenseKey as _LK
        lk = db_session.query(_LK).filter_by(id=key_id).first()
        if not lk:
            return jsonify({'error': 'Key not found'}), 404
        expires_str = data.get('expires_at')  # ISO string or null
        if expires_str:
            try:
                lk.expires_at = _dt.fromisoformat(expires_str.replace('Z', '+00:00').replace('+00:00', ''))
            except ValueError:
                return jsonify({'error': 'Invalid date format (use ISO 8601)'}), 400
        else:
            lk.expires_at = None
        db_session.commit()
        return jsonify({'success': True, 'expires_at': lk.expires_at.isoformat() if lk.expires_at else None})
    finally:
        db_session.close()


@app.route('/admin/api/licenses/grant', methods=['POST'])
@require_admin
def admin_api_grant_license():
    """Manually issue a license key for a user (admin override, bypasses tier check)."""
    import secrets as _secrets
    from datetime import datetime as _dt
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip()
    tier  = str(data.get('tier', '')).strip()
    label = str(data.get('label', 'Admin-Issued'))[:100].strip() or 'Admin-Issued'
    expires_str = data.get('expires_at')

    if not email:
        return jsonify({'error': 'email is required'}), 400
    if tier not in ('pro', 'team', 'enterprise'):
        return jsonify({'error': 'tier must be pro, team, or enterprise'}), 400

    owner = auth_manager.get_user_by_email(email)
    if not owner:
        return jsonify({'error': f'No user found with email: {email}'}), 404

    expires_at = None
    if expires_str:
        try:
            expires_at = _dt.fromisoformat(expires_str.replace('Z', '+00:00').replace('+00:00', ''))
        except ValueError:
            return jsonify({'error': 'Invalid date format (use ISO 8601)'}), 400

    key_val = 'sl_' + _secrets.token_urlsafe(40)
    db_session = auth_manager.get_session()
    try:
        from auth import LicenseKey as _LK
        lk = _LK(
            user_id=owner['id'],
            key=key_val,
            tier=tier,
            label=label,
            expires_at=expires_at,
        )
        db_session.add(lk)
        db_session.commit()
        d = lk.to_dict()
        d['owner_email'] = email
        return jsonify({'key': d}), 201
    finally:
        db_session.close()


# ==================== Employee Onboarding API ====================

@app.route('/admin/api/onboarding/request', methods=['POST'])
def admin_api_onboarding_request():
    """Submit a new employee onboarding request (public endpoint)"""
    data = request.get_json()
    
    # Validate required fields
    required = ['email', 'username', 'password', 'full_name']
    for field in required:
        if not data.get(field, '').strip():
            return jsonify({'success': False, 'error': f'{field.replace("_", " ").title()} is required'}), 400
    
    result = admin_manager.submit_onboarding_request(
        email=data.get('email', '').strip(),
        username=data.get('username', '').strip(),
        password=data.get('password'),
        full_name=data.get('full_name', '').strip(),
        phone=data.get('phone', '').strip() or None,
        requested_role=data.get('requested_role', 'support'),
        reason=data.get('reason', '').strip() or None,
        department=data.get('department', '').strip() or None
    )
    
    if result['success']:
        return jsonify(result)
    return jsonify(result), 400


@app.route('/admin/api/onboarding/verify/<token>', methods=['GET'])
def admin_api_onboarding_verify(token):
    """Verify email for onboarding request"""
    result = admin_manager.verify_onboarding_email(token)
    if result['success']:
        return jsonify(result)
    return jsonify(result), 400


@app.route('/admin/api/onboarding/stats', methods=['GET'])
@require_admin_role('manager')
def admin_api_onboarding_stats():
    """Get onboarding statistics"""
    stats = admin_manager.get_onboarding_stats()
    return jsonify(stats)


@app.route('/admin/api/onboarding/requests', methods=['GET'])
@require_admin_role('manager')
def admin_api_onboarding_requests():
    """Get all onboarding requests"""
    status = request.args.get('status')
    requests = admin_manager.get_pending_requests(status=status)
    return jsonify(requests)


@app.route('/admin/api/onboarding/requests/<int:request_id>', methods=['GET'])
@require_admin_role('manager')
def admin_api_onboarding_request_detail(request_id):
    """Get a specific onboarding request"""
    req = admin_manager.get_pending_request(request_id)
    if req:
        return jsonify(req)
    return jsonify({'error': 'Request not found'}), 404


@app.route('/admin/api/onboarding/requests/<int:request_id>/approve', methods=['POST'])
@require_admin_role('manager')
def admin_api_onboarding_approve(request_id):
    """Approve an onboarding request"""
    data = request.get_json() or {}
    
    result = admin_manager.approve_onboarding_request(
        request_id=request_id,
        reviewer_id=request.current_employee.get('id'),
        approved_role=data.get('role'),
        notes=data.get('notes')
    )
    
    if result['success']:
        return jsonify(result)
    return jsonify(result), 400


@app.route('/admin/api/onboarding/requests/<int:request_id>/reject', methods=['POST'])
@require_admin_role('manager')
def admin_api_onboarding_reject(request_id):
    """Reject an onboarding request"""
    data = request.get_json() or {}
    
    result = admin_manager.reject_onboarding_request(
        request_id=request_id,
        reviewer_id=request.current_employee.get('id'),
        reason=data.get('reason')
    )
    
    if result['success']:
        return jsonify(result)
    return jsonify(result), 400


# ==================== Database Monitoring API ====================

@app.route('/admin/api/database/stats', methods=['GET'])
@require_admin
def admin_api_database_stats():
    """Get comprehensive database statistics for monitoring"""
    from sqlalchemy import inspect, text
    from database import (
        VerificationRecord, WhitelistedDomain, BlacklistedDomain, 
        ShortLink, CommunityReport, Organization, ThreatEvent
    )
    from auth import User
    from admin import Employee, SupportTicket
    
    try:
        session = db.get_session()
        
        # Determine database type
        db_url = config.DATABASE_URL if config.DATABASE_URL else f'sqlite:///{config.DATABASE_PATH}'
        db_type = 'PostgreSQL' if 'postgresql' in db_url or 'postgres' in db_url else 'SQLite'
        
        # Get table counts
        tables = {}
        tables['verification_records'] = session.query(VerificationRecord).count()
        tables['users'] = session.query(User).count()
        tables['short_links'] = session.query(ShortLink).count()
        tables['whitelisted_domains'] = session.query(WhitelistedDomain).count()
        tables['blacklisted_domains'] = session.query(BlacklistedDomain).count()
        tables['community_reports'] = session.query(CommunityReport).count()
        tables['organizations'] = session.query(Organization).count()
        tables['threat_events'] = session.query(ThreatEvent).count()
        tables['support_tickets'] = session.query(SupportTicket).count()
        tables['employees'] = session.query(Employee).count()
        
        # Total records
        total_records = sum(tables.values())
        
        # Risk level distribution
        risk_levels = {}
        for level in ['safe', 'low', 'medium', 'high', 'critical']:
            risk_levels[level] = session.query(VerificationRecord).filter(
                VerificationRecord.risk_level == level
            ).count()
        
        # Threats blocked (unsafe verifications)
        threats_blocked = session.query(VerificationRecord).filter(
            VerificationRecord.is_safe == False
        ).count()
        
        # Recent verifications
        recent = session.query(VerificationRecord).order_by(
            VerificationRecord.created_at.desc()
        ).limit(10).all()
        recent_verifications = [v.to_dict() for v in recent]
        
        session.close()
        
        return jsonify({
            'database_type': db_type,
            'total_tables': len(tables),
            'total_records': total_records,
            'tables': tables,
            'risk_levels': risk_levels,
            'threats_blocked': threats_blocked,
            'recent_verifications': recent_verifications
        })
        
    except Exception as e:
        logger.error(f"Error fetching database stats: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500


# ==================== Customer Support Ticket Submission ====================

@app.route('/api/support/tickets', methods=['POST'])
@require_auth
def create_support_ticket():
    """Allow customers to submit support tickets"""
    data = request.get_json()
    user = request.current_user
    
    subject = data.get('subject', '').strip()
    description = data.get('description', '').strip()
    category = data.get('category', 'general')
    priority = data.get('priority', 'medium')
    
    if not subject or not description:
        return jsonify({'error': 'Subject and description are required'}), 400
    
    result = admin_manager.create_ticket(
        customer_email=user.get('email'),
        customer_name=user.get('full_name') or user.get('username'),
        subject=subject,
        description=description,
        category=category,
        priority=priority,
        user_id=user.get('id'),
        source='web'
    )
    
    if result['success']:
        return jsonify(result)
    return jsonify(result), 400


@app.route('/api/support/tickets/guest', methods=['POST'])
@limiter.limit("3 per hour")
def create_guest_support_ticket():
    """Allow guests (non-logged-in users) to submit support tickets"""
    data = request.get_json()
    
    customer_email = data.get('customer_email', '').strip()
    customer_name = data.get('customer_name', '').strip()
    subject = data.get('subject', '').strip()
    description = data.get('description', '').strip()
    category = data.get('category', 'general')
    priority = data.get('priority', 'medium')
    
    if not customer_email or not subject or not description:
        return jsonify({'error': 'Email, subject, and description are required'}), 400
    
    # Basic email validation
    import re
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', customer_email):
        return jsonify({'error': 'Invalid email address'}), 400
    
    result = admin_manager.create_ticket(
        customer_email=customer_email,
        customer_name=customer_name or 'Guest',
        subject=subject,
        description=description,
        category=category,
        priority=priority,
        user_id=None,
        source='web'
    )
    
    if result['success']:
        return jsonify(result)
    return jsonify(result), 400


@app.route('/api/support/tickets', methods=['GET'])
@require_auth
def get_my_support_tickets():
    """Get current user's support tickets"""
    user_id = request.current_user.get('id')
    tickets = admin_manager.get_customer_tickets(user_id=user_id)
    return jsonify({'tickets': tickets})


@app.route('/api/support/tickets/<int:ticket_id>/respond', methods=['POST'])
@require_auth
def customer_ticket_respond(ticket_id):
    """Allow customer to respond to their ticket"""
    data = request.get_json()
    message = data.get('message', '').strip()
    user_id = request.current_user.get('id')
    
    if not message:
        return jsonify({'error': 'Message is required'}), 400
    
    # Verify the ticket belongs to this user
    ticket = admin_manager.get_ticket(ticket_id=ticket_id)
    if not ticket or ticket.get('user_id') != user_id:
        return jsonify({'error': 'Ticket not found'}), 404
    
    result = admin_manager.add_ticket_response(
        ticket_id=ticket_id,
        message=message,
        is_customer_response=True
    )
    
    if result['success']:
        return jsonify(result)
    return jsonify(result), 400


# ============================================================================
# PASSWORD BREACH CHECKER ROUTES
# ============================================================================

@app.route('/api/breach/password', methods=['POST'])
@limiter.limit("10 per minute")
@require_pro
def check_password_breach_route():
    """Check if a password has been exposed in data breaches (requires Pro)"""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    result = check_password_breach(password)
    return jsonify(result)


@app.route('/api/breach/email', methods=['POST'])
@limiter.limit("10 per minute")
@require_auth
def check_email_breach_route():
    """Check if an email has been in data breaches (requires Pro)"""
    user = request.current_user
    
    # Check if user has Pro subscription
    if user.get('subscription_tier', 'free') == 'free':
        return jsonify({'error': 'Email breach check requires Pro subscription'}), 403
    
    data = request.get_json()
    email = data.get('email', '')
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    result = check_email_breach(email)
    return jsonify(result)


# ============================================================================
# SAFE LINK SHORTENER ROUTES
# ============================================================================

@app.route('/api/shorten', methods=['POST'])
@require_pro
def create_short_link():
    """Create a shortened, pre-verified link (requires Pro)"""
    import traceback
    user = request.current_user
    data = request.get_json()
    original_url = data.get('url', '').strip()
    if not original_url:
        return jsonify({'error': 'URL is required'}), 400
    try:
        # First verify the link
        result = verifier.verify_link(original_url)
        # Create short link with verification status
        short_link = db.create_short_link(
            url=original_url,
            is_safe=result.risk_score < 50,
            risk_score=result.risk_score,
            user_id=user.get('id')
        )
        if short_link:
            base_url = request.host_url.rstrip('/')
            short_url = f"{base_url}/s/{short_link['short_code']}"
            return jsonify({
                'success': True,
                'short_url': short_url,
                'short_code': short_link['short_code'],
                'original_url': original_url,
                'is_safe': short_link['is_safe'],
                'risk_score': result.risk_score
            })
        else:
            app.logger.error(f"Failed to create short link for URL: {original_url} | User: {user.get('id')}")
            return jsonify({'error': 'Failed to create short link'}), 500
    except Exception as e:
        tb = traceback.format_exc()
        app.logger.error(f"Exception in /api/shorten: {e}\n{tb}")
        return jsonify({'error': 'An internal error occurred'}), 500


@app.route('/s/<short_code>')
def redirect_short_link(short_code):
    """Redirect from short link with safety warning"""
    short_link = db.get_short_link(short_code)
    
    if not short_link:
        return render_template('error.html', message='Link not found'), 404
    
    # Track click
    db.track_short_link_click(short_code)
    
    # If link is safe, redirect directly
    if short_link['is_safe']:
        return redirect(short_link['original_url'])
    
    # If link is risky, show warning page
    return render_template('link_warning.html', 
                         short_link=short_link,
                         risk_score=short_link['risk_score'])


@app.route('/api/shorten/stats', methods=['GET'])
@require_pro
def get_short_link_stats():
    """Get user's short link statistics (requires Pro)"""
    user = request.current_user
    links = db.get_user_short_links(user.get('id'))
    
    total_clicks = sum(link.get('click_count', 0) for link in links)
    
    return jsonify({
        'links': links,
        'total_links': len(links),
        'total_clicks': total_clicks
    })


# ============================================================================
# COMMUNITY REPORTING ROUTES
# ============================================================================

@app.route('/api/community/report', methods=['POST'])
@require_auth
def submit_community_report():
    """Submit a suspicious link report"""
    user = request.current_user
    data = request.get_json()
    
    url = data.get('url', '').strip()
    report_type = data.get('report_type', 'suspicious')
    description = data.get('description', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    report = db.create_community_report(
        url=url,
        reported_by=user.get('id'),
        report_type=report_type,
        description=description
    )
    
    if report:
        # Award karma for reporting
        db.update_user_reputation(user.get('id'), karma_change=5)
        return jsonify({
            'success': True,
            'report_id': report['id'],
            'message': 'Thank you for your report! You earned 5 karma points.'
        })
    
    return jsonify({'error': 'Failed to submit report'}), 500


@app.route('/api/community/reports', methods=['GET'])
def get_community_reports():
    """Get recent community reports"""
    status = request.args.get('status', 'pending')
    limit = int(request.args.get('limit', 20))
    
    reports = db.get_community_reports(status=status, limit=limit)
    return jsonify({'reports': reports})


@app.route('/api/community/report/<int:report_id>/vote', methods=['POST'])
@require_auth
def vote_on_report(report_id):
    """Vote on a community report"""
    user = request.current_user
    data = request.get_json()
    is_upvote = data.get('is_upvote', True)
    
    result = db.vote_on_report(
        report_id=report_id,
        user_id=user.get('id'),
        is_upvote=is_upvote
    )
    
    if result['success']:
        return jsonify(result)
    return jsonify(result), 400


@app.route('/api/community/leaderboard', methods=['GET'])
def get_community_leaderboard():
    """Get top contributors leaderboard"""
    limit = int(request.args.get('limit', 10))
    leaderboard = db.get_reputation_leaderboard(limit=limit)
    return jsonify({'leaderboard': leaderboard})


@app.route('/api/community/my-reputation', methods=['GET'])
@require_auth
def get_my_reputation():
    """Get current user's reputation"""
    user = request.current_user
    reputation = db.get_user_reputation(user.get('id'))
    return jsonify(reputation)


# ============================================================================
# REAL-TIME THREAT MAP ROUTES
# ============================================================================

@app.route('/api/threatmap/events', methods=['GET'])
def get_threat_map_events():
    """Get recent threat events for the map"""
    hours = int(request.args.get('hours', 24))
    limit = int(request.args.get('limit', 100))
    
    events = db.get_recent_threat_events(hours=hours, limit=limit)
    return jsonify({'events': events})


@app.route('/api/threatmap/stats', methods=['GET'])
def get_threat_map_stats():
    """Get threat statistics by country"""
    stats = db.get_threat_stats_by_country()
    return jsonify({'stats': stats})


@app.route('/api/threatmap/fetch-live', methods=['POST'])
@limiter.limit("5 per minute")
@require_auth
def fetch_live_threats():
    """Fetch real threats from AbuseIPDB (requires authentication)"""
    import os
    from features import fetch_abuseipdb_recent_reports
    
    threats_added = 0
    
    # Check if AbuseIPDB API key is configured
    if not os.environ.get('ABUSEIPDB_API_KEY'):
        return jsonify({
            'success': False, 
            'error': 'AbuseIPDB API key not configured',
            'count': 0,
            'sources': {'abuseipdb': 0}
        }), 400
    
    try:
        abuseipdb_threats = fetch_abuseipdb_recent_reports(limit=50)
        for threat in abuseipdb_threats:
            db.record_threat_event(
                threat_type=threat['threat_type'],
                url=threat.get('domain'),
                country_code=threat['country_code'],
                latitude=threat['latitude'],
                longitude=threat['longitude'],
                severity=threat['severity']
            )
            threats_added += 1
    except Exception as e:
        logger.error(f"AbuseIPDB fetch error: {e}", exc_info=True)
        return jsonify({
            'success': False, 
            'error': 'An internal error occurred',
            'count': 0,
            'sources': {'abuseipdb': 0}
        }), 500
    
    return jsonify({
        'success': True, 
        'count': threats_added,
        'sources': {
            'abuseipdb': threats_added
        }
    })


@app.route('/api/threatmap/check-ip/<ip>', methods=['GET'])
def check_ip_abuse(ip):
    """Check an IP's reputation using AbuseIPDB"""
    from features import check_ip_reputation
    result = check_ip_reputation(ip)
    return jsonify(result)


# ============================================================================
# ORGANIZATION / ENTERPRISE ROUTES
# ============================================================================

@app.route('/api/org/create', methods=['POST'])
@require_enterprise
def create_organization():
    """Create a new organization (requires Enterprise)"""
    user = request.current_user
    data = request.get_json()
    
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Organization name is required'}), 400
    
    org = db.create_organization(name=name, owner_id=user.get('id'))
    
    if org:
        # Add creator as admin
        db.add_organization_member(
            org_id=org['id'],
            user_id=user.get('id'),
            role='admin'
        )
        return jsonify({
            'success': True,
            'organization': org
        })
    
    return jsonify({'error': 'Failed to create organization'}), 500


@app.route('/api/org/<int:org_id>', methods=['GET'])
@require_enterprise
def get_organization(org_id):
    """Get organization details (requires Enterprise)"""
    user = request.current_user
    org = db.get_organization(org_id)
    
    if not org:
        return jsonify({'error': 'Organization not found'}), 404
    
    # Check if user is a member
    if not db.is_organization_member(org_id, user.get('id')):
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({'organization': org})


@app.route('/api/org/<int:org_id>/members', methods=['GET'])
@require_enterprise
def get_organization_members(org_id):
    """Get organization members (requires Enterprise)"""
    user = request.current_user
    
    if not db.is_organization_member(org_id, user.get('id')):
        return jsonify({'error': 'Access denied'}), 403
    
    members = db.get_organization_members(org_id)
    return jsonify({'members': members})


@app.route('/api/org/<int:org_id>/invite', methods=['POST'])
@require_enterprise
def invite_organization_member(org_id):
    """Invite a user to the organization (requires Enterprise)"""
    user = request.current_user
    data = request.get_json()
    
    # Check if user is admin
    member = db.get_organization_member(org_id, user.get('id'))
    if not member or member.get('role') != 'admin':
        return jsonify({'error': 'Only admins can invite members'}), 403
    
    email = data.get('email', '').strip()
    role = data.get('role', 'member')
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    # Find user by email
    invited_user = auth_manager.get_user_by_email_only(email)
    if not invited_user:
        return jsonify({'error': 'User not found'}), 404
    
    result = db.add_organization_member(
        org_id=org_id,
        user_id=invited_user.get('id'),
        role=role
    )
    
    if result:
        return jsonify({'success': True, 'message': f'{email} has been invited'})
    return jsonify({'error': 'Failed to add member'}), 500


@app.route('/api/org/<int:org_id>/webhooks', methods=['PUT'])
@require_enterprise
def update_organization_webhooks(org_id):
    """Update organization webhook settings (requires Enterprise)"""
    user = request.current_user
    data = request.get_json()
    
    # Check if user is admin
    member = db.get_organization_member(org_id, user.get('id'))
    if not member or member.get('role') != 'admin':
        return jsonify({'error': 'Only admins can update webhooks'}), 403
    
    result = db.update_organization_webhooks(
        org_id=org_id,
        slack_webhook=data.get('slack_webhook'),
        discord_webhook=data.get('discord_webhook'),
        teams_webhook=data.get('teams_webhook')
    )
    
    if result:
        return jsonify({'success': True, 'message': 'Webhooks updated'})
    return jsonify({'error': 'Failed to update webhooks'}), 500


@app.route('/api/org/<int:org_id>/verify', methods=['POST'])
@require_enterprise
def organization_verify_link(org_id):
    """Verify a link for an organization with webhook notifications (requires Enterprise)"""
    user = request.current_user
    data = request.get_json()
    
    if not db.is_organization_member(org_id, user.get('id')):
        return jsonify({'error': 'Access denied'}), 403
    
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Verify the link
    result = verifier.verify_link(url)
    
    # Get AI explanation for dangerous links
    ai_explanation = None
    if result.risk_score >= 50:
        ai_explanation = get_ai_threat_explanation(
            url=url,
            risk_score=result.risk_score,
            threat_types=result.threat_types,
            threat_details=result.threat_details
        )
    
    # Record threat event for threat map
    if result.risk_score >= 50:
        location = get_threat_location(url)
        if location:
            db.record_threat_event(
                threat_type=result.threat_types[0] if result.threat_types else 'unknown',
                url=url,
                country_code=location.get('country_code', 'XX'),
                latitude=location.get('latitude', 0),
                longitude=location.get('longitude', 0),
                severity='high' if result.risk_score >= 70 else 'medium'
            )
    
    # Send webhook notifications for dangerous links
    org = db.get_organization(org_id)
    if result.risk_score >= 50 and org:
        threat_data = {
            'url': url,
            'risk_score': result.risk_score,
            'threat_types': result.threat_types,
            'verified_by': user.get('username'),
            'ai_explanation': ai_explanation
        }
        
        if org.get('slack_webhook'):
            send_slack_notification(org['slack_webhook'], threat_data)
        if org.get('discord_webhook'):
            send_discord_notification(org['discord_webhook'], threat_data)
        if org.get('teams_webhook'):
            send_teams_notification(org['teams_webhook'], threat_data)
    
    return jsonify({
        'success': True,
        'url': url,
        'is_safe': result.risk_score < 50,
        'risk_score': result.risk_score,
        'threat_types': result.threat_types,
        'threat_details': result.threat_details,
        'ai_explanation': ai_explanation
    })


@app.route('/api/org/<int:org_id>/stats', methods=['GET'])
@require_enterprise
def get_organization_stats(org_id):
    """Get organization verification statistics (requires Enterprise)"""
    user = request.current_user
    
    if not db.is_organization_member(org_id, user.get('id')):
        return jsonify({'error': 'Access denied'}), 403
    
    stats = db.get_organization_stats(org_id)
    return jsonify({'stats': stats})


# ============================================================================
# CORPORATE GATEWAY — Zscaler-style URL firewall
# ============================================================================

# Default policy applied when no org policy has been configured
_DEFAULT_POLICY = {
    'risk_threshold': 0.5,       # block if risk_score >= this value (0.0–1.0)
    'block_categories': [        # threat categories that are always blocked
        'phishing', 'malware', 'ransomware', 'credential_harvesting',
        'typosquatting', 'suspicious_redirect',
    ],
    'custom_blocked_domains': [],
    'custom_allowed_domains': [],
    'log_allowed': True,         # also log ALLOW verdicts (full audit trail)
}


def _apply_gateway_policy(url: str, result, policy: dict, org: dict) -> tuple:
    """
    Apply org policy to a VerificationResult.
    Returns (verdict: 'allow'|'block', reason: str|None).
    """
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.lower().lstrip('www.')

    # 1. Custom allow-list — always pass, skip further checks
    allowed_domains = policy.get('custom_allowed_domains', [])
    if any(domain == d.lower().lstrip('www.') for d in allowed_domains):
        return 'allow', None

    # 2. Custom block-list (org-level + policy-level)
    blocked_domains = list(policy.get('custom_blocked_domains', []))
    blocked_domains += org.get('custom_blocked_domains', [])
    if any(domain == d.lower().lstrip('www.') for d in blocked_domains):
        return 'block', f'Domain explicitly blocked by org policy: {domain}'

    # 3. Threat category blocks
    block_cats = set(policy.get('block_categories', []))
    for threat in (result.threats_detected or []):
        threat_key = threat.lower().replace(' ', '_')
        if threat_key in block_cats:
            return 'block', f'Blocked category: {threat}'

    # 4. Risk-score threshold
    threshold = float(policy.get('risk_threshold', 0.5))
    if result.risk_score >= threshold:
        return 'block', f'Risk score {result.risk_score:.2f} exceeds threshold {threshold:.2f}'

    return 'allow', None


@app.route('/api/gateway/check', methods=['POST'])
@limiter.limit("120 per minute")
def gateway_check():
    """
    Corporate gateway endpoint — authenticate with org API key.

    POST body (JSON):
        { "url": "https://example.com", "user_id": 42 }   # user_id optional

    Returns:
        { "verdict": "allow"|"block", "reason": "...", "risk_score": 0.0,
          "risk_level": "safe", "threats": [], "log_id": 123 }
    """
    # ---------- API key authentication ----------
    api_key = (
        request.headers.get('X-API-Key') or
        request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
    )
    if not api_key:
        return jsonify({'error': 'API key required (X-API-Key header)'}), 401

    org = db.get_org_by_api_key(api_key)
    if not org:
        return jsonify({'error': 'Invalid API key'}), 401

    # ---------- Enterprise subscription check ----------
    owner = auth_manager.get_user_by_id(org['owner_id'])
    if not owner or owner.get('subscription_tier') != SubscriptionTier.ENTERPRISE.value:
        return jsonify({'error': 'Gateway requires an active Enterprise subscription'}), 403
    if not _subscription_is_active(owner):
        return jsonify({'error': 'Enterprise subscription has expired. Please renew to continue using the gateway.'}), 403

    # ---------- Input validation ----------
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    if not url:
        return jsonify({'error': 'url is required'}), 400
    if len(url) > 2048:
        return jsonify({'error': 'URL too long'}), 400

    caller_user_id = data.get('user_id')
    source_ip = _get_client_ip()

    # ---------- Threat analysis ----------
    result = verifier.verify_link(url)

    # ---------- Policy enforcement ----------
    policy = {**_DEFAULT_POLICY, **db.get_org_policy(org['id'])}
    verdict, reason = _apply_gateway_policy(url, result, policy, org)

    # ---------- Audit log ----------
    log_allowed = policy.get('log_allowed', True)
    log_id = None
    if verdict == 'block' or log_allowed:
        log_id = db.log_gateway_check(
            org_id=org['id'],
            url=url,
            verdict=verdict,
            block_reason=reason,
            risk_score=result.risk_score,
            risk_level=result.risk_level.value,
            threats=result.threats_detected,
            user_id=caller_user_id,
            source_ip=source_ip,
        )

    # ---------- Webhook alert on block ----------
    if verdict == 'block' and (org.get('has_slack') or org.get('has_discord') or org.get('has_teams')):
        full_org = db.get_organization(org['id'])
        threat_data = {
            'url': url,
            'risk_score': result.risk_score * 100,
            'threat_types': result.threats_detected,
            'verified_by': f'gateway (user_id={caller_user_id})',
            'block_reason': reason,
        }
        if full_org.get('slack_webhook'):
            send_slack_notification(full_org['slack_webhook'], threat_data)
        if full_org.get('discord_webhook'):
            send_discord_notification(full_org['discord_webhook'], threat_data)
        if full_org.get('teams_webhook'):
            send_teams_notification(full_org['teams_webhook'], threat_data)

    return jsonify({
        'verdict': verdict,
        'reason': reason,
        'risk_score': round(result.risk_score, 4),
        'risk_level': result.risk_level.value,
        'threats': result.threats_detected,
        'warnings': result.warnings,
        'log_id': log_id,
        'org_id': org['id'],
    })


@app.route('/api/org/<int:org_id>/policy', methods=['GET'])
@require_enterprise
def get_org_policy(org_id):
    """Return the current gateway policy for an org"""
    user = request.current_user
    if not db.is_organization_member(org_id, user.get('id')):
        return jsonify({'error': 'Access denied'}), 403
    policy = {**_DEFAULT_POLICY, **db.get_org_policy(org_id)}
    return jsonify({'policy': policy})


@app.route('/api/org/<int:org_id>/policy', methods=['PUT'])
@require_enterprise
def set_org_policy(org_id):
    """Update gateway policy for an org (admin only)"""
    user = request.current_user
    member = db.get_organization_member(org_id, user.get('id'))
    if not member or member.get('role') not in ('admin', 'owner'):
        return jsonify({'error': 'Only admins can update policy'}), 403

    data = request.get_json(silent=True) or {}

    # Validate risk_threshold range
    threshold = data.get('risk_threshold', _DEFAULT_POLICY['risk_threshold'])
    try:
        threshold = float(threshold)
        if not (0.0 <= threshold <= 1.0):
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({'error': 'risk_threshold must be a float between 0.0 and 1.0'}), 400

    policy = {
        'risk_threshold': threshold,
        'block_categories': [str(c) for c in data.get('block_categories', _DEFAULT_POLICY['block_categories'])],
        'custom_blocked_domains': [str(d) for d in data.get('custom_blocked_domains', [])],
        'custom_allowed_domains': [str(d) for d in data.get('custom_allowed_domains', [])],
        'log_allowed': bool(data.get('log_allowed', True)),
    }

    if db.set_org_policy(org_id, policy):
        return jsonify({'success': True, 'policy': policy})
    return jsonify({'error': 'Failed to save policy'}), 500


@app.route('/api/org/<int:org_id>/gateway/logs', methods=['GET'])
@require_enterprise
def get_gateway_logs(org_id):
    """Paginated audit log of all gateway checks for an org"""
    user = request.current_user
    if not db.is_organization_member(org_id, user.get('id')):
        return jsonify({'error': 'Access denied'}), 403

    limit  = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))
    verdict_filter = request.args.get('verdict')   # 'allow' | 'block'

    logs  = db.get_gateway_logs(org_id, limit=limit, offset=offset, verdict_filter=verdict_filter)
    stats = db.get_gateway_stats(org_id)
    return jsonify({'logs': logs, 'stats': stats})


# ============================================================================
# ORG NAMED-USER SEAT LICENSING  (Adobe-style)
# ============================================================================

def _require_org_admin(org_id: int, user: dict):
    """Return (member, error_response) — error_response is None when user is an org admin."""
    if not db.is_organization_member(org_id, user.get('id')):
        return None, (jsonify({'error': 'Access denied'}), 403)
    member = db.get_organization_member(org_id, user.get('id'))
    if not member or member.get('role') not in ('owner', 'admin'):
        return None, (jsonify({'error': 'Only org admins can manage licenses'}), 403)
    return member, None


@app.route('/api/org/<int:org_id>/licenses', methods=['GET'])
@require_enterprise
def get_org_licenses(org_id):
    """Return the active license plan + all seats for this org."""
    user = request.current_user
    if not db.is_organization_member(org_id, user.get('id')):
        return jsonify({'error': 'Access denied'}), 403

    plan  = db.get_org_license_plan(org_id)
    seats = db.get_org_seats(org_id) if plan else []
    from payments import TEAM_SEAT_PRICES
    return jsonify({
        'plan':  plan,
        'seats': seats,
        'seat_prices': TEAM_SEAT_PRICES,
    })


@app.route('/api/org/<int:org_id>/licenses/checkout', methods=['POST'])
@require_enterprise
def org_licenses_checkout(org_id):
    """Create a Stripe checkout session to purchase team seats."""
    user = request.current_user
    member, err = _require_org_admin(org_id, user)
    if err:
        return err

    data           = request.get_json(silent=True) or {}
    tier           = str(data.get('tier', 'enterprise')).strip()
    billing_period = str(data.get('billing_period', 'monthly')).strip()
    try:
        seat_count = int(data.get('seat_count', 1))
    except (TypeError, ValueError):
        seat_count = 1

    if tier not in ('pro', 'team', 'enterprise'):
        return jsonify({'error': 'tier must be pro, team, or enterprise'}), 400
    if billing_period not in ('monthly', 'yearly'):
        return jsonify({'error': 'billing_period must be monthly or yearly'}), 400
    if not (1 <= seat_count <= 1000):
        return jsonify({'error': 'seat_count must be between 1 and 1000'}), 400

    # Ensure Stripe customer exists for this user
    customer_id = user.get('stripe_customer_id')
    if not customer_id and payment_manager.is_configured():
        customer_id = payment_manager.create_customer(
            email=user.get('email'), name=user.get('full_name')
        )
        if customer_id:
            auth_manager.update_stripe_customer_id(user['id'], customer_id)

    base_url = request.host_url.rstrip('/')
    session = payment_manager.create_team_checkout_session(
        customer_id=customer_id or 'demo',
        tier=tier,
        seat_count=seat_count,
        billing_period=billing_period,
        success_url=f'{base_url}/organization?payment=success&org_id={org_id}',
        cancel_url=f'{base_url}/organization?payment=cancelled&org_id={org_id}',
        user_id=user['id'],
        org_id=org_id,
    )

    if not session:
        return jsonify({'error': 'Failed to create checkout session'}), 500

    # Demo mode: provision immediately without Stripe
    if session.get('demo_mode'):
        from datetime import timedelta
        expires_at = datetime.utcnow() + timedelta(days=30)
        plan = db.create_org_license_plan(
            org_id=org_id,
            tier=tier,
            seat_count=seat_count,
            purchased_by=user['id'],
            billing_period=billing_period,
            expires_at=expires_at,
        )
        # Auto-assign a seat to the org owner
        db.assign_org_seat(
            plan_id=plan['id'],
            org_id=org_id,
            email=user['email'],
            assigned_by=user['id'],
            tier=tier,
        )
        return jsonify({'demo_mode': True, 'plan': plan})

    return jsonify({'checkout_url': session['url'], 'session_id': session['session_id']})


@app.route('/api/org/<int:org_id>/licenses/assign', methods=['POST'])
@require_enterprise
def assign_org_seat(org_id):
    """Assign a seat to a named user (by email)."""
    user = request.current_user
    member, err = _require_org_admin(org_id, user)
    if err:
        return err

    plan = db.get_org_license_plan(org_id)
    if not plan:
        return jsonify({'error': 'No active license plan found. Purchase seats first.'}), 404
    if not plan.get('seats_available', 0):
        return jsonify({'error': 'No seats available. Purchase additional seats to continue.'}), 403

    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    import re as _re
    if not email or not _re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({'error': 'A valid email address is required'}), 400

    result = db.assign_org_seat(
        plan_id=plan['id'],
        org_id=org_id,
        email=email,
        assigned_by=user['id'],
        tier=plan['tier'],
    )
    if not result.get('success'):
        return jsonify({'error': result.get('error', 'Failed to assign seat')}), 400

    return jsonify({
        'success': True,
        'seat': result['seat'],
        'activated': result.get('activated', False),
        'message': (
            f"Seat activated for {email}."
            if result.get('activated')
            else f"Seat reserved for {email}. They'll be activated when they create an account."
        ),
    }), 201


@app.route('/api/org/<int:org_id>/licenses/seats/<int:seat_id>', methods=['DELETE'])
@require_enterprise
def revoke_org_seat(org_id, seat_id):
    """Revoke a seat and downgrade the user if needed."""
    user = request.current_user
    member, err = _require_org_admin(org_id, user)
    if err:
        return err

    result = db.revoke_org_seat(seat_id=seat_id, org_id=org_id)
    if not result.get('success'):
        return jsonify({'error': result.get('error', 'Failed to revoke seat')}), 400
    return jsonify({'success': True})


@app.route('/api/org/<int:org_id>/licenses/prices', methods=['GET'])
@require_enterprise
def get_org_license_prices(org_id):
    """Return per-seat pricing for the checkout UI."""
    from payments import TEAM_SEAT_PRICES
    return jsonify({'seat_prices': TEAM_SEAT_PRICES})


# ============================================================================
# AI THREAT EXPLANATION ROUTE
# ============================================================================

@app.route('/api/explain-threat', methods=['POST'])
@require_auth
def explain_threat():
    """Get AI explanation for a threat"""
    data = request.get_json()
    
    url = data.get('url', '')
    risk_score = data.get('risk_score', 0)
    threat_types = data.get('threat_types', [])
    threat_details = data.get('threat_details', {})
    
    explanation = get_ai_threat_explanation(
        url=url,
        risk_score=risk_score,
        threat_types=threat_types,
        threat_details=threat_details
    )
    
    return jsonify({
        'explanation': explanation
    })


# ==================== FORUM / COMMUNITY CHAT ROUTES ====================

@app.route('/forum')
def forum_page():
    """Redirect to community page with discussions tab"""
    return redirect('/community')


@app.route('/api/forum/categories', methods=['GET'])
def get_forum_categories():
    """Get all forum categories"""
    session = db.get_session()
    try:
        categories = session.query(ForumCategory).filter_by(is_active=True).order_by(ForumCategory.sort_order).all()
        return jsonify({
            'categories': [cat.to_dict() for cat in categories]
        })
    finally:
        session.close()


@app.route('/api/forum/categories', methods=['POST'])
@require_auth
def create_forum_category():
    """Create a new forum category (admin only in future)"""
    data = request.get_json()
    
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    icon = data.get('icon', 'fa-comments')
    color = data.get('color', 'blue')
    
    if not name:
        return jsonify({'error': 'Category name is required'}), 400
    
    # Create slug from name
    import re
    slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
    
    session = db.get_session()
    try:
        # Check if category exists
        existing = session.query(ForumCategory).filter_by(slug=slug).first()
        if existing:
            return jsonify({'error': 'Category already exists'}), 400
        
        category = ForumCategory(
            name=name,
            slug=slug,
            description=description,
            icon=icon,
            color=color
        )
        session.add(category)
        session.commit()
        
        return jsonify({
            'success': True,
            'category': category.to_dict()
        })
    except Exception as e:
        session.rollback()
        logger.error(f"Operation failed: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500
    finally:
        session.close()


@app.route('/api/forum/posts', methods=['GET'])
def get_forum_posts():
    """Get posts, optionally filtered by category"""
    category_slug = request.args.get('category')
    sort_by = request.args.get('sort', 'newest')  # newest, top, hot
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    session = db.get_session()
    try:
        query = session.query(ForumPost).filter_by(is_deleted=False)
        
        # Filter by category if provided
        if category_slug:
            category = session.query(ForumCategory).filter_by(slug=category_slug).first()
            if category:
                query = query.filter_by(category_id=category.id)
        
        # Sort posts
        if sort_by == 'top':
            query = query.order_by((ForumPost.upvotes - ForumPost.downvotes).desc())
        elif sort_by == 'hot':
            # Hot = score + recency bonus
            query = query.order_by(ForumPost.is_pinned.desc(), ForumPost.upvotes.desc(), ForumPost.created_at.desc())
        else:  # newest
            query = query.order_by(ForumPost.is_pinned.desc(), ForumPost.created_at.desc())
        
        # Paginate
        total = query.count()
        posts = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Get category info for each post
        category_ids = list(set(p.category_id for p in posts))
        categories_map = {}
        if category_ids:
            cats = session.query(ForumCategory).filter(ForumCategory.id.in_(category_ids)).all()
            categories_map = {c.id: c.to_dict() for c in cats}
        
        posts_data = []
        for post in posts:
            post_dict = post.to_dict(include_content=False)
            post_dict['category'] = categories_map.get(post.category_id)
            posts_data.append(post_dict)
        
        return jsonify({
            'posts': posts_data,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })
    finally:
        session.close()


@app.route('/api/forum/posts', methods=['POST'])
@require_auth
def create_forum_post():
    """Create a new forum post"""
    data = request.get_json()
    
    category_id = data.get('category_id')
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    
    if not category_id:
        return jsonify({'error': 'Category is required'}), 400
    if not title or len(title) < 5:
        return jsonify({'error': 'Title must be at least 5 characters'}), 400
    if not content or len(content) < 10:
        return jsonify({'error': 'Content must be at least 10 characters'}), 400
    if len(title) > 300:
        return jsonify({'error': 'Title too long (max 300 characters)'}), 400
    
    user = request.current_user
    
    session = db.get_session()
    try:
        # Verify category exists
        category = session.query(ForumCategory).filter_by(id=category_id, is_active=True).first()
        if not category:
            return jsonify({'error': 'Invalid category'}), 400
        
        post = ForumPost(
            category_id=category_id,
            author_id=user['id'],
            author_username=user.get('username', user.get('email', 'Anonymous')),
            title=title,
            content=content
        )
        session.add(post)
        
        # Increment category post count
        category.post_count += 1
        
        session.commit()
        
        return jsonify({
            'success': True,
            'post': post.to_dict()
        })
    except Exception as e:
        session.rollback()
        logger.error(f"Operation failed: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500
    finally:
        session.close()


@app.route('/api/forum/posts/<int:post_id>', methods=['GET'])
def get_forum_post(post_id):
    """Get a single post with its comments"""
    session = db.get_session()
    try:
        post = session.query(ForumPost).filter_by(id=post_id, is_deleted=False).first()
        if not post:
            return jsonify({'error': 'Post not found'}), 404
        
        # Increment view count
        post.view_count += 1
        session.commit()
        
        # Get category
        category = session.query(ForumCategory).filter_by(id=post.category_id).first()
        
        # Get comments
        comments = session.query(ForumComment).filter_by(
            post_id=post_id, 
            is_deleted=False
        ).order_by(ForumComment.created_at.asc()).all()
        
        post_dict = post.to_dict()
        post_dict['category'] = category.to_dict() if category else None
        
        return jsonify({
            'post': post_dict,
            'comments': [c.to_dict() for c in comments]
        })
    finally:
        session.close()


@app.route('/api/forum/posts/<int:post_id>/comments', methods=['POST'])
@require_auth
def create_forum_comment(post_id):
    """Add a comment to a post"""
    data = request.get_json()
    content = data.get('content', '').strip()
    parent_id = data.get('parent_id')
    
    if not content or len(content) < 2:
        return jsonify({'error': 'Comment must be at least 2 characters'}), 400
    
    user = request.current_user
    
    session = db.get_session()
    try:
        # Verify post exists and is not locked
        post = session.query(ForumPost).filter_by(id=post_id, is_deleted=False).first()
        if not post:
            return jsonify({'error': 'Post not found'}), 404
        if post.is_locked:
            return jsonify({'error': 'This post is locked'}), 403
        
        comment = ForumComment(
            post_id=post_id,
            parent_id=parent_id,
            author_id=user['id'],
            author_username=user.get('username', user.get('email', 'Anonymous')),
            content=content
        )
        session.add(comment)
        
        # Increment post comment count
        post.comment_count += 1
        
        session.commit()
        
        return jsonify({
            'success': True,
            'comment': comment.to_dict()
        })
    except Exception as e:
        session.rollback()
        logger.error(f"Operation failed: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500
    finally:
        session.close()


@app.route('/api/forum/vote', methods=['POST'])
@require_auth
def forum_vote():
    """Vote on a post or comment"""
    data = request.get_json()
    
    post_id = data.get('post_id')
    comment_id = data.get('comment_id')
    vote_value = data.get('vote', 0)  # 1, -1, or 0 (remove vote)
    
    if not post_id and not comment_id:
        return jsonify({'error': 'Must specify post_id or comment_id'}), 400
    if vote_value not in [-1, 0, 1]:
        return jsonify({'error': 'Invalid vote value'}), 400
    
    user = request.current_user
    
    session = db.get_session()
    try:
        # Find existing vote
        vote_query = session.query(ForumVote).filter_by(user_id=user['id'])
        if post_id:
            vote_query = vote_query.filter_by(post_id=post_id, comment_id=None)
            target = session.query(ForumPost).filter_by(id=post_id).first()
        else:
            vote_query = vote_query.filter_by(comment_id=comment_id, post_id=None)
            target = session.query(ForumComment).filter_by(id=comment_id).first()
        
        if not target:
            return jsonify({'error': 'Target not found'}), 404
        
        existing_vote = vote_query.first()
        old_vote_value = existing_vote.vote if existing_vote else 0
        
        # Update vote counts on target
        if old_vote_value == 1:
            target.upvotes -= 1
        elif old_vote_value == -1:
            target.downvotes -= 1
        
        if vote_value == 1:
            target.upvotes += 1
        elif vote_value == -1:
            target.downvotes += 1
        
        # Update or create vote record
        if vote_value == 0:
            if existing_vote:
                session.delete(existing_vote)
        else:
            if existing_vote:
                existing_vote.vote = vote_value
            else:
                new_vote = ForumVote(
                    user_id=user['id'],
                    post_id=post_id if post_id else None,
                    comment_id=comment_id if comment_id else None,
                    vote=vote_value
                )
                session.add(new_vote)
        
        session.commit()
        
        return jsonify({
            'success': True,
            'upvotes': target.upvotes,
            'downvotes': target.downvotes,
            'score': target.upvotes - target.downvotes
        })
    except Exception as e:
        session.rollback()
        logger.error(f"Operation failed: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500
    finally:
        session.close()


@app.route('/api/forum/my-votes', methods=['GET'])
@require_auth
def get_my_forum_votes():
    """Get current user's votes for display"""
    post_ids = request.args.get('post_ids', '')
    comment_ids = request.args.get('comment_ids', '')
    
    user = request.current_user
    
    session = db.get_session()
    try:
        votes = {}
        
        if post_ids:
            pids = [int(p) for p in post_ids.split(',') if p.isdigit()]
            post_votes = session.query(ForumVote).filter(
                ForumVote.user_id == user['id'],
                ForumVote.post_id.in_(pids)
            ).all()
            for v in post_votes:
                votes[f'post_{v.post_id}'] = v.vote
        
        if comment_ids:
            cids = [int(c) for c in comment_ids.split(',') if c.isdigit()]
            comment_votes = session.query(ForumVote).filter(
                ForumVote.user_id == user['id'],
                ForumVote.comment_id.in_(cids)
            ).all()
            for v in comment_votes:
                votes[f'comment_{v.comment_id}'] = v.vote
        
        return jsonify({'votes': votes})
    finally:
        session.close()


@app.route('/api/forum/seed-categories', methods=['POST'])
@limiter.limit("3 per minute")
def seed_forum_categories():
    """Seed default forum categories (admin only - requires ADMIN_SECRET_KEY)"""
    data = request.get_json() or {}
    secret_key = data.get('secret_key', '')
    expected_key = Config.ADMIN_SECRET_KEY
    if not expected_key or secret_key != expected_key:
        return jsonify({'error': 'Unauthorized'}), 401
    
    session = db.get_session()
    try:
        # Check if categories already exist
        existing = session.query(ForumCategory).count()
        if existing > 0:
            return jsonify({'message': 'Categories already exist', 'count': existing})
        
        default_categories = [
            {'name': 'General Discussion', 'slug': 'general', 'description': 'Talk about anything security-related', 'icon': 'fa-comments', 'color': 'blue', 'sort_order': 1},
            {'name': 'Phishing Reports', 'slug': 'phishing', 'description': 'Report and discuss phishing attempts', 'icon': 'fa-fish', 'color': 'red', 'sort_order': 2},
            {'name': 'Scam Alerts', 'slug': 'scams', 'description': 'Warn others about scams you\'ve encountered', 'icon': 'fa-exclamation-triangle', 'color': 'yellow', 'sort_order': 3},
            {'name': 'Security Tips', 'slug': 'tips', 'description': 'Share and learn security best practices', 'icon': 'fa-lightbulb', 'color': 'green', 'sort_order': 4},
            {'name': 'Help & Support', 'slug': 'help', 'description': 'Get help with SecureLink or security questions', 'icon': 'fa-question-circle', 'color': 'purple', 'sort_order': 5},
        ]
        
        for cat_data in default_categories:
            category = ForumCategory(**cat_data)
            session.add(category)
        
        session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Created {len(default_categories)} categories'
        })
    except Exception as e:
        session.rollback()
        logger.error(f"Operation failed: {e}", exc_info=True)
        return jsonify({'error': 'An internal error occurred'}), 500
    finally:
        session.close()


def setup_logging():
    """Set up file logging"""
    file_handler = RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    file_handler.setLevel(getattr(logging, config.LOG_LEVEL))
    
    app.logger.addHandler(file_handler)
    app.logger.setLevel(getattr(logging, config.LOG_LEVEL))


if __name__ == '__main__':
    setup_logging()
    logger.info("Starting SecureLink...")
    
    # Start weekly report scheduler (sends reports every Monday at 9 AM)
    report_generator.start_scheduler(auth_manager, day='monday', hour=9)
    
    # Start hourly threat report scheduler (sends alerts when threats detected)
    report_generator.start_hourly_scheduler(auth_manager)
    
    # Start support email monitor (auto-creates tickets from support@securelinkapp.com)
    if config.SUPPORT_EMAIL_ADDRESS:
        start_support_email_monitor(config, interval=config.SUPPORT_EMAIL_CHECK_INTERVAL)
        logger.info(f"Support email monitor started for {config.SUPPORT_EMAIL_ADDRESS}")
    
    # Start attack surface scan scheduler
    scan_scheduler = get_scan_scheduler(config)
    scan_scheduler.start()
    logger.info("Attack surface scan scheduler started")
    
    try:
        print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                 SecureLink - Starting Up                   ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  Web Interface: http://localhost:5000                     ║
    ║                                                           ║
    ║  Features:                                                ║
    ║  • User accounts with persistent login (stay signed in)   ║
    ║  • Paste links to verify their safety                     ║
    ║  • Attack Surface Monitoring (domain security scans)      ║
    ║  • Dark web monitoring for Pro users                      ║
    ║  • Desktop notifications for dangerous links              ║
    ║  • Hourly threat alerts via email                         ║
    ║  • Weekly security reports via email                      ║
    ║  • Free & Pro subscription tiers                          ║
    ║                                                           ║
    ║  New user? Visit http://localhost:5000/login              ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    except UnicodeEncodeError:
        print("SecureLink starting on http://localhost:5000")
    
    # Bind to localhost only — in production, gunicorn sits behind nginx on 0.0.0.0.
    # The dev server should never be directly internet-facing.
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=config.DEBUG
    )
