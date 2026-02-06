"""
SecureLink - Flask Web Application
Main entry point for the web interface with user authentication.

Copyright (c) 2026 Ryan Haley. All Rights Reserved.
This software is proprietary and confidential.
"""
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
from datetime import datetime, timedelta

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_cors import CORS
from sqlalchemy import and_

from config import Config
from link_verifier import LinkVerifier, VerificationResult
from email_monitor import EmailMonitor, EmailLink
from notifications import NotificationService
from database import Database
from auth import AuthManager, SUBSCRIPTION_PLANS, SubscriptionTier
from weekly_reports import WeeklyReportGenerator, get_report_generator
from payments import PaymentManager, get_payment_manager, PLAN_PRICES
from oauth import init_oauth, get_configured_providers, get_oauth_client, parse_user_info, generate_username_from_email
from cyber_news import get_cyber_news
from admin import get_admin_manager, EmployeeRole
from features import (
    get_ai_threat_explanation, check_password_breach, check_email_breach,
    send_slack_notification, send_discord_notification, send_teams_notification,
    get_threat_location, generate_demo_threat_events
)

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
CORS(app)

# Initialize services
config = Config()
verifier = LinkVerifier(config)
db = Database(config)
notification_service = NotificationService(config)
auth_manager = AuthManager(config)
report_generator = get_report_generator()
payment_manager = get_payment_manager(config)
admin_manager = get_admin_manager(config)

# Initialize OAuth
oauth = init_oauth(app, config)

# Store email monitors per user
user_email_monitors = {}


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


def require_pro(f):
    """Decorator to require Pro subscription"""
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        if request.current_user.get('subscription_tier') == SubscriptionTier.FREE.value:
            return jsonify({'error': 'This feature requires a Pro subscription'}), 403
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


def on_email_link_found_for_user(user_id: int, email_account: str = None, monitor = None):
    """Create callback for email link found"""
    def callback(link: EmailLink, result: VerificationResult):
        from link_verifier import RiskLevel
        
        # Save to database with email account info
        db.save_verification(
            result,
            source='email',
            email_subject=link.email_subject,
            email_from=link.email_from,
            email_account=email_account,
            user_id=user_id
        )
        
        # Check for high-risk links
        is_high_risk = result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        
        # Send notification if unsafe
        if not result.is_safe:
            account_info = f" ({email_account})" if email_account else ""
            notification_service.notify(result, f"Email{account_info}: {link.email_subject}")
        
        # For high-risk links: quarantine and send detailed report
        if is_high_risk and monitor:
            logger.warning(f"HIGH RISK link detected for user {user_id}: {link.url} - Risk: {result.risk_level.value}")
            
            # Quarantine the email
            quarantine_success = monitor.quarantine_email(link.email_uid)
            if quarantine_success:
                logger.info(f"Email {link.email_uid} quarantined successfully")
            else:
                logger.error(f"Failed to quarantine email {link.email_uid}")
            
            # Send detailed threat report
            report_sent = monitor.send_threat_report(link, result, email_account)
            if report_sent:
                logger.info(f"Threat report sent to {email_account}")
            else:
                logger.error(f"Failed to send threat report for email {link.email_uid}")
        
        logger.info(f"Email link verified for user {user_id} ({email_account}): {link.url} - Safe: {result.is_safe}")
    
    return callback


def start_monitoring_for_user(user_id: int):
    """Start email monitoring for all active accounts of a user"""
    # Stop existing monitors if running
    if user_id in user_email_monitors and user_email_monitors[user_id]:
        for monitor in user_email_monitors[user_id]:
            try:
                monitor.stop_monitoring()
            except:
                pass
    
    # Get user's active email accounts
    accounts = auth_manager.get_active_email_accounts(user_id)
    
    if not accounts:
        user_email_monitors[user_id] = None
        return
    
    # Create monitors for all active accounts
    monitors = []
    
    for account in accounts:
        try:
            # Test connection first
            from imapclient import IMAPClient
            test_client = IMAPClient(
                account['host'],
                port=account['port'],
                ssl=True
            )
            test_client.login(account['email'], account['password'])
            test_client.logout()
            
            # Connection works, start monitoring
            user_config = Config()
            user_config.EMAIL_USERNAME = account['email']
            user_config.EMAIL_PASSWORD = account['password']
            user_config.EMAIL_HOST = account['host']
            user_config.EMAIL_PORT = account['port']
            
            # Create monitor first, then set callback with monitor reference
            monitor = EmailMonitor(user_config)
            monitor.on_link_found = on_email_link_found_for_user(user_id, account['email'], monitor)
            monitor.start_monitoring()
            monitors.append(monitor)
            logger.info(f"Started monitoring for {account['email']}")
            
        except Exception as e:
            logger.error(f"Error starting monitor for {account['email']}: {e}")
            auth_manager.update_email_account_status(account['id'], checked=True, error=str(e))
    
    user_email_monitors[user_id] = monitors if monitors else None


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


@app.route('/profile')
def profile_page():
    """Render the profile page"""
    return render_template('profile.html')


@app.route('/guide')
def guide_page():
    """Render the user guide page"""
    return render_template('guide.html')


@app.route('/features')
def features_page():
    """Render the features overview page"""
    return render_template('features.html')


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
def register():
    """Register a new user"""
    data = request.get_json()
    
    email = data.get('email', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    full_name = data.get('full_name', '').strip()
    
    if not email or not username or not password:
        return jsonify({'success': False, 'error': 'Email, username, and password are required'}), 400
    
    if len(password) < 8:
        return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
    
    result = auth_manager.register(email, username, password, full_name)
    return jsonify(result)


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate user and create session"""
    data = request.get_json()
    
    email_or_username = data.get('email_or_username', '').strip()
    password = data.get('password', '')
    remember_me = data.get('remember_me', False)
    
    if not email_or_username or not password:
        return jsonify({'success': False, 'error': 'Credentials required'}), 400
    
    result = auth_manager.login(
        email_or_username,
        password,
        remember_me=remember_me,
        device_info=request.headers.get('User-Agent'),
        ip_address=request.remote_addr
    )
    
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


@app.route('/api/admin/emergency-reset', methods=['POST'])
def emergency_password_reset():
    """Emergency password reset endpoint - requires secret key"""
    data = request.get_json()
    
    # Require a secret key for security
    secret_key = data.get('secret_key', '')
    if secret_key != 'SecureLink2026EmergencyReset!':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    email = data.get('email', '').strip()
    new_password = data.get('new_password', '')
    
    if not email or not new_password:
        return jsonify({'success': False, 'error': 'Email and new_password required'}), 400
    
    result = auth_manager.reset_password_by_email(email, new_password)
    return jsonify(result)


@app.route('/api/admin/check-user', methods=['POST'])
def check_user_exists():
    """Check if user exists in database - requires secret key"""
    data = request.get_json()
    
    secret_key = data.get('secret_key', '')
    if secret_key != 'SecureLink2026EmergencyReset!':
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
                    'email': user.email,
                    'username': user.username,
                    'has_password': bool(user.password_hash),
                    'has_salt': bool(user.salt),
                    'is_active': user.is_active,
                    'created_at': str(user.created_at) if user.created_at else None
                }
            })
        else:
            # List all users for debugging
            all_users = session.query(User).limit(10).all()
            return jsonify({
                'success': True,
                'found': False,
                'total_users': len(all_users),
                'sample_emails': [u.email for u in all_users]
            })
    finally:
        session.close()


@app.route('/api/admin/reset-admin-password', methods=['POST'])
def reset_admin_password():
    """Reset admin/employee password - requires secret key"""
    data = request.get_json()
    
    secret_key = data.get('secret_key', '')
    if secret_key != 'SecureLink2026EmergencyReset!':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    username = data.get('username', '').strip()
    new_password = data.get('new_password', '')
    
    if not username or not new_password:
        return jsonify({'success': False, 'error': 'Username and new_password required'}), 400
    
    # Reset admin/employee password
    import hashlib
    import secrets as sec
    from admin import Employee
    
    admin_session = admin_manager.get_session()
    try:
        employee = admin_session.query(Employee).filter(Employee.username == username).first()
        if not employee:
            return jsonify({'success': False, 'error': f'Employee {username} not found'})
        
        salt = sec.token_hex(32)
        password_hash = hashlib.sha256((new_password + salt).encode()).hexdigest()
        
        employee.salt = salt
        employee.password_hash = password_hash
        admin_session.commit()
        
        return jsonify({'success': True, 'message': f'Password reset for admin user: {username}'})
    except Exception as e:
        admin_session.rollback()
        return jsonify({'success': False, 'error': str(e)})
    finally:
        admin_session.close()


# ============== Browser Extension API ==============

# Track daily scans per user (in-memory, resets on server restart)
# In production, use Redis or database
extension_scan_counts = {}

def get_scan_limit(subscription_tier):
    """Get daily scan limit based on subscription tier"""
    limits = {
        'free': 10,
        'pro': 500,
        'enterprise': float('inf')  # Unlimited
    }
    return limits.get(subscription_tier, 10)

@app.route('/api/extension/auth', methods=['POST'])
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
        ip_address=request.remote_addr
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


@app.route('/api/extension/status', methods=['GET'])
def extension_status():
    """Get extension status and remaining scans for authenticated user"""
    token = get_token_from_request()
    
    if not token:
        # Anonymous user - very limited access
        return jsonify({
            'authenticated': False,
            'subscription_tier': 'anonymous',
            'scan_limit': 5,
            'scans_remaining': 5,
            'message': 'Sign in for more scans'
        })
    
    user_data = auth_manager.validate_token(token)
    if not user_data:
        return jsonify({
            'authenticated': False,
            'subscription_tier': 'anonymous',
            'scan_limit': 5,
            'scans_remaining': 5,
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
    
    remaining = max(0, limit - scans_today) if limit != float('inf') else 'unlimited'
    
    return jsonify({
        'authenticated': True,
        'user': {
            'email': user.get('email'),
            'username': user.get('username')
        },
        'subscription_tier': tier,
        'scan_limit': limit if limit != float('inf') else 'unlimited',
        'scans_today': scans_today,
        'scans_remaining': remaining
    })


@app.route('/api/extension/verify', methods=['POST'])
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
    limit = 5
    
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
    key = f"{user_id or request.remote_addr}:{today}"
    scans_today = extension_scan_counts.get(key, 0)
    
    if limit != float('inf') and scans_today >= limit:
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
        'risk_level': result.risk_level,
        'threats_detected': result.threats_detected,
        'warnings': result.warnings,
        'subscription_tier': tier,
        'scans_remaining': max(0, limit - scans_today - 1) if limit != float('inf') else 'unlimited'
    }
    
    return jsonify(response)


@app.route('/api/auth/change-password', methods=['POST'])
@require_auth
def change_password():
    """Change user password"""
    data = request.get_json()
    
    result = auth_manager.change_password(
        request.current_user['id'],
        data.get('old_password', ''),
        data.get('new_password', '')
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
                ip_address=request.remote_addr
            )
            if auth_token:
                # Redirect to home with token in URL (will be stored by JS)
                return redirect(f'/?oauth_token={auth_token}')
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
                ip_address=request.remote_addr
            )
            if auth_token:
                return redirect(f'/?oauth_token={auth_token}')
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
                ip_address=request.remote_addr
            )
            if auth_token:
                return redirect(f'/?oauth_token={auth_token}&welcome=true')
        
        return redirect('/login?error=Failed to create account')
        
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        return redirect(f'/login?error=OAuth authentication failed')


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
            ip_address=request.remote_addr
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
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        session.close()


# ============== Email Account Routes (Multiple Accounts) ==============

@app.route('/api/email-accounts', methods=['GET'])
@require_pro
def get_email_accounts():
    """Get all email accounts for the user"""
    accounts = auth_manager.get_email_accounts(request.current_user['id'])
    count_info = auth_manager.get_email_account_count(request.current_user['id'])
    return jsonify({
        'accounts': accounts,
        'count': count_info
    })


@app.route('/api/email-accounts', methods=['POST'])
@require_pro
def add_email_account():
    """Add a new email account for monitoring"""
    data = request.get_json()
    user_id = request.current_user['id']
    
    required = ['email', 'host', 'port', 'password']
    if not all(k in data for k in required):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    result = auth_manager.add_email_account(
        user_id=user_id,
        email=data['email'],
        host=data['host'],
        port=data['port'],
        password=data['password'],
        label=data.get('label')
    )
    
    # Auto-start monitoring for this user if account was added successfully
    if result.get('success'):
        try:
            start_monitoring_for_user(user_id)
        except Exception as e:
            logger.error(f"Error auto-starting monitor: {e}")
    
    return jsonify(result)


@app.route('/api/email-accounts/<int:account_id>', methods=['GET'])
@require_pro
def get_email_account(account_id):
    """Get a specific email account"""
    account = auth_manager.get_email_account(request.current_user['id'], account_id)
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    return jsonify(account)


@app.route('/api/email-accounts/<int:account_id>', methods=['PUT'])
@require_pro
def update_email_account(account_id):
    """Update an email account"""
    data = request.get_json()
    user_id = request.current_user['id']
    result = auth_manager.update_email_account(
        user_id=user_id,
        account_id=account_id,
        data=data
    )
    
    # Restart monitoring if is_active was changed
    if result.get('success') and 'is_active' in data:
        try:
            start_monitoring_for_user(user_id)
        except Exception as e:
            logger.error(f"Error restarting monitor: {e}")
    
    return jsonify(result)


@app.route('/api/email-accounts/<int:account_id>', methods=['DELETE'])
@require_pro
def delete_email_account(account_id):
    """Delete an email account"""
    user_id = request.current_user['id']
    result = auth_manager.delete_email_account(
        user_id=user_id,
        account_id=account_id
    )
    
    # Restart monitoring after deletion
    if result.get('success'):
        try:
            start_monitoring_for_user(user_id)
        except Exception as e:
            logger.error(f"Error restarting monitor: {e}")
    return jsonify(result)


@app.route('/api/email-accounts/<int:account_id>/test', methods=['POST'])
@require_pro
def test_email_account(account_id):
    """Test connection for a specific email account"""
    data = request.get_json() or {}
    
    # Get the existing account to use stored credentials if not provided
    account = auth_manager.get_email_account(request.current_user['id'], account_id)
    if not account:
        return jsonify({'success': False, 'error': 'Account not found'}), 404
    
    # Use provided data or fall back to stored values
    host = data.get('host') or account.get('host', 'imap.gmail.com')
    port = data.get('port') or account.get('port', 993)
    email = data.get('email') or account.get('email')
    password = data.get('password')
    
    # If no password provided, try to get stored password
    if not password:
        password = auth_manager.get_email_account_password(request.current_user['id'], account_id)
    
    if not password:
        return jsonify({'success': False, 'error': 'Password required for testing'}), 400
    
    try:
        from imapclient import IMAPClient
        
        client = IMAPClient(host, port=port, ssl=True)
        client.login(email, password)
        client.logout()
        
        # Update account status - mark as verified
        auth_manager.update_email_account_status(account_id, checked=True, error=None)
        
        return jsonify({'success': True, 'message': 'Connection successful! Account verified.'})
    except Exception as e:
        auth_manager.update_email_account_status(account_id, checked=True, error=str(e))
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/email-accounts/test-new', methods=['POST'])
@require_pro
def test_new_email_account():
    """Test connection for a new email account before adding"""
    data = request.get_json()
    
    try:
        from imapclient import IMAPClient
        
        client = IMAPClient(
            data.get('host', 'imap.gmail.com'),
            port=data.get('port', 993),
            ssl=True
        )
        client.login(data.get('email'), data.get('password'))
        client.logout()
        
        return jsonify({'success': True, 'message': 'Connection successful'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ============== Legacy Email Settings (for backward compatibility) ==============

@app.route('/api/email-settings', methods=['GET'])
@require_pro
def get_email_settings():
    """Get user's email monitoring settings (legacy - redirects to accounts)"""
    settings = auth_manager.get_email_settings(request.current_user['id'])
    return jsonify(settings)


@app.route('/api/email-settings', methods=['PUT'])
@require_pro
def update_email_settings():
    """Update email monitoring settings (legacy)"""
    data = request.get_json()
    result = auth_manager.update_email_settings(request.current_user['id'], data)
    return jsonify(result)


@app.route('/api/email-settings/test', methods=['POST'])
@require_pro
def test_email_connection():
    """Test email connection (legacy)"""
    data = request.get_json()
    
    try:
        from imapclient import IMAPClient
        
        client = IMAPClient(
            data.get('host', 'imap.gmail.com'),
            port=data.get('port', 993),
            ssl=True
        )
        client.login(data.get('email'), data.get('password'))
        client.logout()
        
        return jsonify({'success': True, 'message': 'Connection successful'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


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
    plan_order = {'free': 0, 'pro': 1, 'enterprise': 2}
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
    
    if plan not in ['pro', 'enterprise']:
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
    plan = data.get('plan')
    
    if not session_id or not plan:
        return jsonify({'error': 'Missing session_id or plan'}), 400
    
    user = request.current_user
    
    # Verify the checkout session with Stripe
    result = payment_manager.verify_checkout_session(session_id)
    
    if result and result.get('success'):
        # Activate the subscription
        from datetime import datetime, timedelta
        expires_at = datetime.utcnow() + timedelta(days=30)
        update_result = auth_manager.update_subscription(user['id'], plan, expires_at)
        
        # Save subscription ID if available
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
            # Payment successful - activate subscription
            user_id = data.get('metadata', {}).get('user_id')
            plan = data.get('metadata', {}).get('plan')
            subscription_id = data.get('subscription')
            
            if user_id and plan:
                expires_at = datetime.utcnow() + timedelta(days=30)
                auth_manager.update_subscription(user_id, plan, expires_at)
                if subscription_id:
                    auth_manager.update_stripe_subscription_id(user_id, subscription_id)
                logger.info(f"Activated {plan} subscription for user {user_id}")
        
        elif event_type == 'invoice.paid':
            # Recurring payment successful - extend subscription
            subscription_id = data.get('subscription')
            if subscription_id:
                # Get subscription details to find user
                sub_details = payment_manager.get_subscription(subscription_id)
                if sub_details:
                    # Would need to look up user by subscription ID
                    logger.info(f"Recurring payment received for subscription {subscription_id}")
        
        elif event_type == 'customer.subscription.deleted':
            # Subscription cancelled/expired - downgrade to free
            subscription_id = data.get('id')
            # Would need to look up user by subscription ID and downgrade
            logger.info(f"Subscription {subscription_id} cancelled")
        
        elif event_type == 'invoice.payment_failed':
            # Payment failed - notify user
            customer_email = data.get('customer_email')
            logger.warning(f"Payment failed for {customer_email}")
    
    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
    
    return jsonify({'received': True})


# ============== Link Verification Routes ==============

# Track anonymous website scan counts (in production, use Redis)
website_anonymous_scans = {}

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
    
    # Rate limit for anonymous users (5 scans/day per IP)
    if is_anonymous:
        from datetime import date
        today = date.today().isoformat()
        ip_key = f"{request.remote_addr}:{today}"
        scans_today = website_anonymous_scans.get(ip_key, 0)
        
        if scans_today >= 5:
            return jsonify({
                'error': 'Daily scan limit reached',
                'message': 'Sign up for free to get 10 scans per day!',
                'limit': 5,
                'used': scans_today,
                'signup_url': '/login'
            }), 429
        
        # Increment anonymous scan count
        website_anonymous_scans[ip_key] = scans_today + 1
    
    try:
        # Verify the link
        result = verifier.verify_link(url)
        
        # Save to database
        db.save_verification(result, source='manual')
        
        # Increment scan count if authenticated
        if user_id:
            auth_manager.increment_scan_count(user_id)
        
        # Send notification if unsafe
        if not result.is_safe:
            notification_service.notify(result)
        
        return jsonify(result.to_dict())
    
    except Exception as e:
        logger.error(f"Error verifying link: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan-file', methods=['POST'])
def scan_file():
    """API endpoint to scan a file for security threats"""
    import re
    import hashlib
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Check file size (max 200MB)
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Seek back to start
    
    max_size = 200 * 1024 * 1024  # 200MB
    if file_size > max_size:
        return jsonify({'error': 'File size exceeds 200MB limit'}), 400
    
    # Get file extension
    filename = file.filename.lower()
    extension = '.' + filename.split('.')[-1] if '.' in filename else ''
    
    allowed_extensions = ['.txt', '.html', '.htm', '.js', '.css', '.json', '.xml', '.csv', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.eml', '.msg']
    if extension not in allowed_extensions:
        return jsonify({'error': 'File type not supported'}), 400
    
    # Check auth for scan limits (optional)
    token = get_token_from_request()
    user_id = None
    
    if token:
        user_data = auth_manager.validate_token(token)
        if user_data:
            user_id = user_data['user']['id']
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
        logger.error(f"Error scanning file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/history', methods=['GET'])
def get_history():
    """Get verification history"""
    limit = request.args.get('limit', 50, type=int)
    try:
        history = db.get_recent_verifications(limit)
        return jsonify(history)
    except Exception as e:
        logger.error(f"Error getting history: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get verification statistics"""
    try:
        stats = db.get_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500


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


# ============== Email Monitoring Routes ==============

@app.route('/api/email-accounts/status', methods=['GET'])
@require_auth
def get_email_accounts_status():
    """Get email accounts status for the navbar indicator"""
    user_id = request.current_user['id']
    tier = request.current_user.get('subscription_tier', 'free')
    
    # Free users don't have email monitoring
    if tier == 'free':
        return jsonify({
            'connected': False,
            'account_count': 0,
            'active_count': 0,
            'monitoring': False
        })
    
    try:
        accounts = auth_manager.get_email_accounts(user_id)
        active_accounts = [a for a in accounts if a.get('is_active')]
        monitoring = user_id in user_email_monitors and user_email_monitors[user_id] is not None
        
        return jsonify({
            'connected': len(active_accounts) > 0,
            'account_count': len(accounts),
            'active_count': len(active_accounts),
            'monitoring': monitoring,
            'accounts': [{'email': a['email'], 'label': a['label'], 'is_active': a['is_active']} for a in accounts]
        })
    except Exception as e:
        logger.error(f"Error getting email status: {e}")
        return jsonify({'connected': False, 'account_count': 0, 'active_count': 0, 'monitoring': False})


@app.route('/api/check-emails', methods=['POST'])
@require_pro
def check_emails():
    """Check all connected email accounts for links"""
    user_id = request.current_user['id']
    
    # Get user's email accounts
    accounts = auth_manager.get_active_email_accounts(user_id)
    
    if not accounts:
        return jsonify({'error': 'No email accounts configured. Go to Profile > Email Settings to connect your email.'}), 400
    
    all_results = []
    errors = []
    
    try:
        for account in accounts:
            try:
                # Test connection first before attempting to check
                from imapclient import IMAPClient
                test_client = IMAPClient(
                    account['host'],
                    port=account['port'],
                    ssl=True
                )
                test_client.login(account['email'], account['password'])
                test_client.logout()
                
                # Create temporary config with this account's settings
                user_config = Config()
                user_config.EMAIL_USERNAME = account['email']
                user_config.EMAIL_PASSWORD = account['password']
                user_config.EMAIL_HOST = account['host']
                user_config.EMAIL_PORT = account['port']
                
                monitor = EmailMonitor(user_config, on_link_found=on_email_link_found_for_user(user_id, account['email']))
                results = monitor.check_emails_once(limit=10)
                
                # Add account info to each result
                for r in results:
                    r['email_account'] = account['email']
                    r['account_label'] = account.get('label', account['email'])
                
                all_results.extend(results)
                
                # Update account status
                auth_manager.update_email_account_status(account['id'], checked=True, error=None)
                
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Error checking account {account['email']}: {error_msg}")
                errors.append({'account': account['email'], 'error': error_msg})
                auth_manager.update_email_account_status(account['id'], checked=True, error=error_msg)
        
        # If all accounts failed, return error
        if not all_results and errors and len(errors) == len(accounts):
            return jsonify({
                'error': 'Failed to check emails. Check your credentials.',
                'errors': errors
            }), 400
        
        return jsonify({
            'results': all_results, 
            'count': len(all_results),
            'accounts_checked': len(accounts) - len(errors),
            'errors': errors
        })
    
    except Exception as e:
        logger.error(f"Error checking emails: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/email/start', methods=['POST'])
@require_pro
def start_email_monitor():
    """Start continuous email monitoring for all active accounts"""
    user_id = request.current_user['id']
    
    # Get user's active email accounts
    accounts = auth_manager.get_active_email_accounts(user_id)
    
    if not accounts:
        return jsonify({'error': 'No email accounts configured. Go to Profile > Email Settings to add accounts.'}), 400
    
    try:
        # Stop existing monitors if running
        if user_id in user_email_monitors:
            for monitor in user_email_monitors[user_id]:
                try:
                    monitor.stop_monitoring()
                except:
                    pass
        
        # Create monitors for all active accounts - test connection first
        monitors = []
        started_accounts = []
        failed_accounts = []
        
        for account in accounts:
            try:
                # Test connection first
                from imapclient import IMAPClient
                test_client = IMAPClient(
                    account['host'],
                    port=account['port'],
                    ssl=True
                )
                test_client.login(account['email'], account['password'])
                test_client.logout()
                
                # Connection works, start monitoring
                user_config = Config()
                user_config.EMAIL_USERNAME = account['email']
                user_config.EMAIL_PASSWORD = account['password']
                user_config.EMAIL_HOST = account['host']
                user_config.EMAIL_PORT = account['port']
                
                # Create monitor first, then set callback with monitor reference
                monitor = EmailMonitor(user_config)
                monitor.on_link_found = on_email_link_found_for_user(user_id, account['email'], monitor)
                monitor.start_monitoring()
                monitors.append(monitor)
                started_accounts.append(account['email'])
                
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Error starting monitor for {account['email']}: {error_msg}")
                failed_accounts.append({'email': account['email'], 'error': error_msg})
                auth_manager.update_email_account_status(account['id'], checked=True, error=error_msg)
        
        user_email_monitors[user_id] = monitors if monitors else None
        
        if not started_accounts and failed_accounts:
            # All accounts failed
            error_details = '; '.join([f"{a['email']}: {a['error']}" for a in failed_accounts])
            return jsonify({
                'error': f'Failed to connect to email accounts. {error_details}',
                'failed_accounts': failed_accounts
            }), 400
        
        return jsonify({
            'status': 'started',
            'accounts': started_accounts,
            'count': len(started_accounts),
            'failed_accounts': failed_accounts
        })
    
    except Exception as e:
        logger.error(f"Error starting email monitor: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/email/stop', methods=['POST'])
@require_pro
def stop_email_monitor():
    """Stop email monitoring for all accounts"""
    user_id = request.current_user['id']
    
    if user_id in user_email_monitors:
        for monitor in user_email_monitors[user_id]:
            try:
                monitor.stop_monitoring()
            except:
                pass
        del user_email_monitors[user_id]
        return jsonify({'status': 'stopped'})
    
    return jsonify({'status': 'not_running'})


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
        logger.error(f"Failed to send test hourly report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


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


# ==================== Admin API Routes ====================

@app.route('/admin/api/login', methods=['POST'])
def admin_api_login():
    """Admin employee login"""
    data = request.get_json()
    email_or_username = data.get('email') or data.get('username')
    password = data.get('password')
    
    if not email_or_username or not password:
        return jsonify({'success': False, 'error': 'Email/username and password required'}), 400
    
    result = admin_manager.login_employee(
        email_or_username, 
        password,
        device_info=request.headers.get('User-Agent'),
        ip_address=request.remote_addr
    )
    
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
        logger.error(f"Error fetching database stats: {e}")
        return jsonify({'error': str(e)}), 500


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
def check_password_breach_route():
    """Check if a password has been exposed in data breaches"""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    result = check_password_breach(password)
    return jsonify(result)


@app.route('/api/breach/email', methods=['POST'])
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
@require_auth
def create_short_link():
    """Create a shortened, pre-verified link"""
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
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


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
@require_auth
def get_short_link_stats():
    """Get user's short link statistics"""
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
def fetch_live_threats():
    """Fetch real threats from AbuseIPDB"""
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
        logger.error(f"AbuseIPDB fetch error: {e}")
        return jsonify({
            'success': False, 
            'error': str(e),
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
@require_auth
def create_organization():
    """Create a new organization"""
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
@require_auth
def get_organization(org_id):
    """Get organization details"""
    user = request.current_user
    org = db.get_organization(org_id)
    
    if not org:
        return jsonify({'error': 'Organization not found'}), 404
    
    # Check if user is a member
    if not db.is_organization_member(org_id, user.get('id')):
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({'organization': org})


@app.route('/api/org/<int:org_id>/members', methods=['GET'])
@require_auth
def get_organization_members(org_id):
    """Get organization members"""
    user = request.current_user
    
    if not db.is_organization_member(org_id, user.get('id')):
        return jsonify({'error': 'Access denied'}), 403
    
    members = db.get_organization_members(org_id)
    return jsonify({'members': members})


@app.route('/api/org/<int:org_id>/invite', methods=['POST'])
@require_auth
def invite_organization_member(org_id):
    """Invite a user to the organization"""
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
@require_auth
def update_organization_webhooks(org_id):
    """Update organization webhook settings"""
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
@require_auth
def organization_verify_link(org_id):
    """Verify a link for an organization (with webhook notifications)"""
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
@require_auth
def get_organization_stats(org_id):
    """Get organization verification statistics"""
    user = request.current_user
    
    if not db.is_organization_member(org_id, user.get('id')):
        return jsonify({'error': 'Access denied'}), 403
    
    stats = db.get_organization_stats(org_id)
    return jsonify({'stats': stats})


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
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                 SecureLink - Starting Up                   ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  Web Interface: http://localhost:5000                     ║
    ║                                                           ║
    ║  Features:                                                ║
    ║  • User accounts with persistent login (stay signed in)   ║
    ║  • Paste links to verify their safety                     ║
    ║  • Email monitoring for Pro users                         ║
    ║  • Desktop notifications for dangerous links              ║
    ║  • Hourly threat alerts via email                         ║
    ║  • Weekly security reports via email                      ║
    ║  • Free & Pro subscription tiers                          ║
    ║                                                           ║
    ║  New user? Visit http://localhost:5000/login              ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=config.DEBUG
    )
