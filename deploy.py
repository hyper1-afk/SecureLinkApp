#!/usr/bin/env python3
"""
SecureLink Deployment Script
Automates deployment to production (Heroku) or other platforms.

Usage:
    python deploy.py              # Interactive deployment
    python deploy.py --check      # Check deployment status
    python deploy.py --push       # Push to production
    python deploy.py --logs       # View production logs

Copyright (c) 2026 Ryan Haley. All Rights Reserved.
"""

import os
import sys
import subprocess
import argparse
from datetime import datetime
from pathlib import Path

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {text}{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.FAIL}✗ {text}{Colors.END}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.WARNING}⚠ {text}{Colors.END}")

def run_command(cmd, capture=False, check=True):
    """Run a shell command"""
    try:
        if capture:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
            return result.returncode == 0, result.stdout.strip()
        else:
            result = subprocess.run(cmd, shell=True, check=check)
            return result.returncode == 0, ""
    except subprocess.CalledProcessError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def check_git():
    """Check if git is configured"""
    success, output = run_command("git status", capture=True, check=False)
    if not success:
        print_error("Not a git repository or git is not installed")
        return False
    print_success("Git repository detected")
    return True

def check_heroku():
    """Check if Heroku CLI is installed and logged in"""
    success, output = run_command("heroku --version", capture=True, check=False)
    if not success:
        print_error("Heroku CLI not installed")
        print_info("Install from: https://devcenter.heroku.com/articles/heroku-cli")
        return False
    print_success(f"Heroku CLI: {output.split()[0]} {output.split()[1] if len(output.split()) > 1 else ''}")
    
    success, output = run_command("heroku auth:whoami", capture=True, check=False)
    if not success or "Error" in output:
        print_warning("Not logged in to Heroku")
        print_info("Run: heroku login")
        return False
    print_success(f"Logged in as: {output}")
    return True

def check_heroku_app():
    """Check if a Heroku app is configured"""
    success, output = run_command("heroku apps:info", capture=True, check=False)
    if not success or "Couldn't find" in output or "Error" in output:
        print_warning("No Heroku app linked to this repository")
        return None
    
    # Parse app name from output
    for line in output.split('\n'):
        if line.startswith('==='):
            app_name = line.replace('===', '').strip()
            print_success(f"Heroku app: {app_name}")
            return app_name
    return None

def get_git_status():
    """Get current git status"""
    success, branch = run_command("git rev-parse --abbrev-ref HEAD", capture=True, check=False)
    if success:
        print_info(f"Current branch: {branch}")
    
    success, status = run_command("git status --porcelain", capture=True, check=False)
    if status:
        uncommitted = len(status.strip().split('\n'))
        print_warning(f"{uncommitted} uncommitted changes")
        return False
    else:
        print_success("Working directory clean")
        return True

def pre_deploy_checks():
    """Run pre-deployment checks"""
    print_header("Pre-Deployment Checks")
    
    checks = {
        "Git": check_git,
        "Heroku CLI": check_heroku,
        "Git Status": get_git_status
    }
    
    results = {}
    for name, check_func in checks.items():
        results[name] = check_func()
    
    app_name = check_heroku_app()
    results["Heroku App"] = app_name is not None
    
    # Check required files
    print("\n" + Colors.BOLD + "Required Files:" + Colors.END)
    required_files = ['Procfile', 'requirements.txt', 'app.py', 'runtime.txt']
    for f in required_files:
        if os.path.exists(f):
            print_success(f"{f} exists")
        else:
            if f == 'runtime.txt':
                print_warning(f"{f} missing (optional - Heroku will use default Python)")
            else:
                print_error(f"{f} missing!")
                results[f] = False
    
    return results, app_name

def commit_changes():
    """Commit any uncommitted changes"""
    print_header("Commit Changes")
    
    success, status = run_command("git status --porcelain", capture=True, check=False)
    if not status:
        print_info("No changes to commit")
        return True
    
    print_info("Uncommitted changes detected:")
    print(status)
    
    response = input(f"\n{Colors.CYAN}Enter commit message (or press Enter to skip): {Colors.END}")
    if response.strip():
        run_command("git add .")
        success, _ = run_command(f'git commit -m "{response}"', check=False)
        if success:
            print_success("Changes committed")
            return True
        else:
            print_error("Failed to commit")
            return False
    return True

def deploy_to_heroku(app_name):
    """Deploy to Heroku"""
    print_header("Deploying to Heroku")
    
    print_info("Pushing to Heroku...")
    success, output = run_command("git push heroku main", check=False)
    
    if not success:
        # Try master branch
        print_info("Trying 'master' branch...")
        success, output = run_command("git push heroku master", check=False)
    
    if success:
        print_success("Deployment successful!")
        print_info(f"App URL: https://{app_name}.herokuapp.com")
        return True
    else:
        print_error("Deployment failed")
        return False

def run_migrations():
    """Run database migrations on Heroku"""
    print_header("Running Database Migrations")
    
    print_info("Running migrations...")
    success, _ = run_command("heroku run python -c 'from database import db; db.create_all()'", check=False)
    
    if success:
        print_success("Migrations complete")
    else:
        print_warning("Migration command finished (check logs for details)")

def view_logs():
    """View Heroku logs"""
    print_header("Heroku Logs")
    run_command("heroku logs --tail", check=False)

def check_status():
    """Check deployment status"""
    print_header("Deployment Status")
    
    if not check_heroku():
        return
    
    app_name = check_heroku_app()
    if not app_name:
        return
    
    print("\n" + Colors.BOLD + "Dyno Status:" + Colors.END)
    run_command("heroku ps", check=False)
    
    print("\n" + Colors.BOLD + "Recent Activity:" + Colors.END)
    run_command("heroku releases -n 5", check=False)
    
    print("\n" + Colors.BOLD + "Config Vars:" + Colors.END)
    success, output = run_command("heroku config", capture=True, check=False)
    # Mask sensitive values
    for line in output.split('\n'):
        if ':' in line:
            key = line.split(':')[0].strip()
            if any(s in key.upper() for s in ['SECRET', 'KEY', 'PASSWORD', 'TOKEN', 'URL']):
                print(f"  {key}: ****")
            else:
                print(f"  {line}")
        else:
            print(f"  {line}")

def set_config_var(key, value):
    """Set a Heroku config variable"""
    success, _ = run_command(f'heroku config:set {key}="{value}"', check=False)
    return success

def interactive_deploy():
    """Interactive deployment wizard"""
    print_header("SecureLink Deployment Wizard")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  Platform: Heroku")
    
    results, app_name = pre_deploy_checks()
    
    # Check if all critical checks passed
    all_passed = all([
        results.get("Git", False),
        results.get("Heroku CLI", False),
        results.get("Heroku App", False)
    ])
    
    if not all_passed:
        print("\n" + Colors.FAIL + "Some checks failed. Please fix the issues above." + Colors.END)
        
        if not results.get("Heroku App"):
            print_info("\nTo create a new Heroku app:")
            print("  1. heroku create your-app-name")
            print("  2. git remote add heroku https://git.heroku.com/your-app-name.git")
        
        return
    
    # Check for uncommitted changes
    if not results.get("Git Status", True):
        commit_changes()
    
    # Confirm deployment
    print("\n" + Colors.WARNING + "Ready to deploy to production!" + Colors.END)
    print(f"  App: {app_name}")
    
    response = input(f"\n{Colors.CYAN}Proceed with deployment? (y/N): {Colors.END}")
    if response.lower() != 'y':
        print_info("Deployment cancelled")
        return
    
    # Deploy
    if deploy_to_heroku(app_name):
        run_migrations()
        
        print("\n" + Colors.GREEN + "="*60 + Colors.END)
        print(f"{Colors.GREEN}  Deployment Complete!{Colors.END}")
        print(f"{Colors.GREEN}  URL: https://{app_name}.herokuapp.com{Colors.END}")
        print(f"{Colors.GREEN}{'='*60}{Colors.END}")

def create_heroku_app():
    """Create a new Heroku app"""
    print_header("Create New Heroku App")
    
    if not check_heroku():
        return
    
    app_name = input(f"{Colors.CYAN}Enter app name (or press Enter for random): {Colors.END}").strip()
    
    if app_name:
        success, output = run_command(f"heroku create {app_name}", capture=True, check=False)
    else:
        success, output = run_command("heroku create", capture=True, check=False)
    
    if success:
        print_success("Heroku app created!")
        print(output)
        
        # Set required config vars
        print_info("\nSetting up config vars...")
        config_vars = {
            'FLASK_ENV': 'production',
            'FLASK_DEBUG': '0'
        }
        
        for key, value in config_vars.items():
            set_config_var(key, value)
            print_success(f"Set {key}")
        
        print_warning("\nDon't forget to set these config vars:")
        print("  - SECRET_KEY (generate a secure key)")
        print("  - DATABASE_URL (auto-set if you add Heroku Postgres)")
        print("  - Any OAuth keys (GOOGLE_CLIENT_ID, etc.)")
        
        # Add Postgres addon
        response = input(f"\n{Colors.CYAN}Add Heroku Postgres database? (Y/n): {Colors.END}")
        if response.lower() != 'n':
            print_info("Adding Postgres...")
            run_command("heroku addons:create heroku-postgresql:mini", check=False)
            print_success("Postgres added (DATABASE_URL auto-configured)")
    else:
        print_error("Failed to create app")
        print(output)

def main():
    parser = argparse.ArgumentParser(description='SecureLink Deployment Tool')
    parser.add_argument('--check', '-c', action='store_true', help='Check deployment status')
    parser.add_argument('--push', '-p', action='store_true', help='Push to production')
    parser.add_argument('--logs', '-l', action='store_true', help='View production logs')
    parser.add_argument('--create', action='store_true', help='Create new Heroku app')
    parser.add_argument('--migrate', '-m', action='store_true', help='Run database migrations')
    
    args = parser.parse_args()
    
    os.chdir(Path(__file__).parent)
    
    if args.check:
        check_status()
    elif args.push:
        results, app_name = pre_deploy_checks()
        if app_name and results.get("Git Status", True):
            deploy_to_heroku(app_name)
    elif args.logs:
        view_logs()
    elif args.create:
        create_heroku_app()
    elif args.migrate:
        run_migrations()
    else:
        interactive_deploy()

if __name__ == '__main__':
    main()
