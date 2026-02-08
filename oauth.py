"""
SecureLink - OAuth Authentication Module
Handles social login with Google, Microsoft, and Yahoo.

Copyright (c) 2026 SecureLink. All rights reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""
import os
import secrets
import logging
from functools import wraps
from authlib.integrations.flask_client import OAuth

logger = logging.getLogger(__name__)

oauth = OAuth()

# OAuth provider configurations
OAUTH_PROVIDERS = {
    'google': {
        'name': 'Google',
        'icon': 'bi-google',
        'color': '#4285f4',
        'client_id_env': 'GOOGLE_CLIENT_ID',
        'client_secret_env': 'GOOGLE_CLIENT_SECRET',
    },
    'microsoft': {
        'name': 'Microsoft',
        'icon': 'bi-microsoft',
        'color': '#00a4ef',
        'client_id_env': 'MICROSOFT_CLIENT_ID',
        'client_secret_env': 'MICROSOFT_CLIENT_SECRET',
    },
    'yahoo': {
        'name': 'Yahoo',
        'icon': 'bi-envelope',  # Yahoo icon not in bootstrap, use envelope
        'color': '#6001d2',
        'client_id_env': 'YAHOO_CLIENT_ID',
        'client_secret_env': 'YAHOO_CLIENT_SECRET',
    }
}


def init_oauth(app, config):
    """Initialize OAuth providers with Flask app"""
    oauth.init_app(app)
    
    # Google OAuth
    google_client_id = getattr(config, 'GOOGLE_CLIENT_ID', None) or os.getenv('GOOGLE_CLIENT_ID')
    google_client_secret = getattr(config, 'GOOGLE_CLIENT_SECRET', None) or os.getenv('GOOGLE_CLIENT_SECRET')
    
    if google_client_id and google_client_secret:
        oauth.register(
            name='google',
            client_id=google_client_id,
            client_secret=google_client_secret,
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={
                'scope': 'openid email profile'
            }
        )
        logger.info("Google OAuth configured")
    else:
        logger.info("Google OAuth not configured - missing credentials")
    
    # Microsoft OAuth (Azure AD)
    microsoft_client_id = getattr(config, 'MICROSOFT_CLIENT_ID', None) or os.getenv('MICROSOFT_CLIENT_ID')
    microsoft_client_secret = getattr(config, 'MICROSOFT_CLIENT_SECRET', None) or os.getenv('MICROSOFT_CLIENT_SECRET')
    
    if microsoft_client_id and microsoft_client_secret:
        oauth.register(
            name='microsoft',
            client_id=microsoft_client_id,
            client_secret=microsoft_client_secret,
            server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
            client_kwargs={
                'scope': 'openid email profile'
            }
        )
        logger.info("Microsoft OAuth configured")
    else:
        logger.info("Microsoft OAuth not configured - missing credentials")
    
    # Yahoo OAuth
    yahoo_client_id = getattr(config, 'YAHOO_CLIENT_ID', None) or os.getenv('YAHOO_CLIENT_ID')
    yahoo_client_secret = getattr(config, 'YAHOO_CLIENT_SECRET', None) or os.getenv('YAHOO_CLIENT_SECRET')
    
    if yahoo_client_id and yahoo_client_secret:
        oauth.register(
            name='yahoo',
            client_id=yahoo_client_id,
            client_secret=yahoo_client_secret,
            authorize_url='https://api.login.yahoo.com/oauth2/request_auth',
            access_token_url='https://api.login.yahoo.com/oauth2/get_token',
            userinfo_endpoint='https://api.login.yahoo.com/openid/v1/userinfo',
            client_kwargs={
                'scope': 'openid email profile'
            }
        )
        logger.info("Yahoo OAuth configured")
    else:
        logger.info("Yahoo OAuth not configured - missing credentials")
    
    return oauth


def get_configured_providers():
    """Return list of configured OAuth providers"""
    configured = []
    
    for provider_id, provider_info in OAUTH_PROVIDERS.items():
        client_id = os.getenv(provider_info['client_id_env'])
        if client_id:
            configured.append({
                'id': provider_id,
                'name': provider_info['name'],
                'icon': provider_info['icon'],
                'color': provider_info['color'],
                'configured': True
            })
        else:
            configured.append({
                'id': provider_id,
                'name': provider_info['name'],
                'icon': provider_info['icon'],
                'color': provider_info['color'],
                'configured': False
            })
    
    return configured


def get_oauth_client(provider):
    """Get OAuth client for a specific provider"""
    try:
        return getattr(oauth, provider)
    except AttributeError:
        return None


def parse_user_info(provider, user_info):
    """Parse user info from OAuth provider into standard format"""
    if provider == 'google':
        return {
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'picture': user_info.get('picture'),
            'email_verified': user_info.get('email_verified', False),
            'provider_id': user_info.get('sub')
        }
    elif provider == 'microsoft':
        return {
            'email': user_info.get('email') or user_info.get('preferred_username'),
            'name': user_info.get('name'),
            'picture': None,  # Microsoft doesn't provide picture in basic profile
            'email_verified': True,  # Microsoft emails are verified
            'provider_id': user_info.get('sub')
        }
    elif provider == 'yahoo':
        return {
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'picture': user_info.get('picture'),
            'email_verified': user_info.get('email_verified', False),
            'provider_id': user_info.get('sub')
        }
    else:
        return {
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'picture': user_info.get('picture'),
            'email_verified': False,
            'provider_id': user_info.get('sub') or user_info.get('id')
        }


def generate_username_from_email(email):
    """Generate a unique username from email"""
    base_username = email.split('@')[0].lower()
    # Remove special characters
    base_username = ''.join(c for c in base_username if c.isalnum() or c == '_')
    # Add random suffix to ensure uniqueness
    return f"{base_username}_{secrets.token_hex(4)}"
