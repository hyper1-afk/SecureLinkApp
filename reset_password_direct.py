"""
Password Reset Script for SecureLink - Direct Version
"""
import os
import sys

# Set up the database connection to production
DATABASE_URL = "postgresql://dev-db-748382:AVNS_-_mAt6xfcsoj8ALfYam@app-f889963a-fcf6-4681-b928-7f70badeea57-do-user-32910661-0.e.db.ondigitalocean.com:25060/dev-db-748382?sslmode=require"
os.environ['DATABASE_URL'] = DATABASE_URL

from auth import AuthManager

# === CHANGE THESE VALUES ===
EMAIL_OR_USERNAME = "ryanhaley2000@gmail.com"
NEW_PASSWORD = "$paceMonkey2001!"
# ===========================

def reset_password():
    auth = AuthManager()
    
    print(f"\nResetting password for: {EMAIL_OR_USERNAME}")
    
    # Try email first, then username
    if '@' in EMAIL_OR_USERNAME:
        result = auth.reset_password_by_email(EMAIL_OR_USERNAME, NEW_PASSWORD)
    else:
        result = auth.reset_password_by_username(EMAIL_OR_USERNAME, NEW_PASSWORD)
    
    if result['success']:
        print(f"✅ {result['message']}")
    else:
        print(f"❌ Error: {result['error']}")

if __name__ == "__main__":
    reset_password()
