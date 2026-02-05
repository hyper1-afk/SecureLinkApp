"""
SecureLink Environment Configuration
Manages local and production database connections.

Copyright (c) 2026 Ryan Haley. All Rights Reserved.
"""

import os
import json
from pathlib import Path

CONFIG_FILE = Path(__file__).parent / '.securelink_env.json'

DEFAULT_CONFIG = {
    'current_environment': 'local',
    'environments': {
        'local': {
            'name': 'Local Development',
            'database_type': 'sqlite',
            'database_path': 'link_verifier.db',
            'database_url': None,
            'app_url': 'http://localhost:5000'
        },
        'production': {
            'name': 'Production',
            'database_type': 'postgresql',
            'database_path': None,
            'database_url': '',  # Set your DATABASE_URL here
            'app_url': ''  # Set your production URL here
        }
    }
}


def load_config():
    """Load configuration from file"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Merge with defaults for any missing keys
                for env in DEFAULT_CONFIG['environments']:
                    if env not in config.get('environments', {}):
                        config.setdefault('environments', {})[env] = DEFAULT_CONFIG['environments'][env]
                return config
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config):
    """Save configuration to file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def get_current_environment():
    """Get the current active environment name"""
    config = load_config()
    return config.get('current_environment', 'local')


def get_environment_config(env_name=None):
    """Get configuration for a specific environment"""
    config = load_config()
    if env_name is None:
        env_name = config.get('current_environment', 'local')
    return config.get('environments', {}).get(env_name, DEFAULT_CONFIG['environments']['local'])


def set_current_environment(env_name):
    """Switch to a different environment"""
    config = load_config()
    if env_name in config.get('environments', {}):
        config['current_environment'] = env_name
        save_config(config)
        return True
    return False


def update_environment(env_name, settings):
    """Update settings for an environment"""
    config = load_config()
    if env_name not in config.get('environments', {}):
        config.setdefault('environments', {})[env_name] = {}
    config['environments'][env_name].update(settings)
    save_config(config)


def get_database_url(env_name=None):
    """Get the database URL for an environment"""
    env = get_environment_config(env_name)
    
    if env.get('database_type') == 'sqlite':
        db_path = env.get('database_path', 'link_verifier.db')
        return f"sqlite:///{db_path}"
    else:
        url = env.get('database_url', '')
        # Handle postgres:// vs postgresql:// format
        if url.startswith('postgres://'):
            url = url.replace('postgres://', 'postgresql://', 1)
        return url


def list_environments():
    """List all configured environments"""
    config = load_config()
    current = config.get('current_environment', 'local')
    envs = []
    for name, settings in config.get('environments', {}).items():
        envs.append({
            'name': name,
            'display_name': settings.get('name', name),
            'is_current': name == current,
            'database_type': settings.get('database_type', 'unknown'),
            'app_url': settings.get('app_url', '')
        })
    return envs


def add_environment(name, display_name, database_type, database_url=None, database_path=None, app_url=''):
    """Add a new environment configuration"""
    config = load_config()
    config.setdefault('environments', {})[name] = {
        'name': display_name,
        'database_type': database_type,
        'database_url': database_url,
        'database_path': database_path,
        'app_url': app_url
    }
    save_config(config)


# Initialize config file if it doesn't exist
if not CONFIG_FILE.exists():
    save_config(DEFAULT_CONFIG)
