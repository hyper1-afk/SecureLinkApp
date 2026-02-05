"""
Password Reset Script for SecureLink
Run this to reset a user's password
"""
import os
import sys

# Set up the database connection to production
DATABASE_URL = "postgresql://dev-db-748382:AVNS_-_mAt6xfcsoj8ALfYam@app-f889963a-fcf6-4681-b928-7f70badeea57-do-user-32910661-0.e.db.ondigitalocean.com:25060/dev-db-748382?sslmode=require"
os.environ['DATABASE_URL'] = DATABASE_URL

from auth import AuthManager

def reset_password():
    auth = AuthManager()
    
    print("\n=== SecureLink Password Reset ===\n")
    
    # Get user input
    identifier = input("Enter username or email: ").strip()
    new_password = input("Enter new password: ").strip()
    
    if not identifier or not new_password:
        print("Error: Both username/email and password are required")
        return
    
    # Try email first, then username
    if '@' in identifier:
        result = auth.reset_password_by_email(identifier, new_password)
    else:
        result = auth.reset_password_by_username(identifier, new_password)
    
    if result['success']:
        print(f"\n✅ {result['message']}")
        print("You can now log in with your new password.")
    else:
        print(f"\n❌ Error: {result['error']}")

if __name__ == "__main__":
    reset_password()
