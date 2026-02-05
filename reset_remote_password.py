"""
Script to reset password on remote PostgreSQL database
Run this with DATABASE_URL environment variable set to the production database
"""
import os
import hashlib
import secrets
from sqlalchemy import create_engine, text

# Get the DATABASE_URL from environment or prompt
DATABASE_URL = os.getenv('DATABASE_URL')

if not DATABASE_URL:
    print("DATABASE_URL not set. Please provide the production database URL:")
    DATABASE_URL = input().strip()

# Convert postgres:// to postgresql:// if needed
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

print(f"Connecting to database...")

def hash_password(password: str, salt: str) -> str:
    """Hash password with salt using SHA-256"""
    return hashlib.sha256((password + salt).encode()).hexdigest()

try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    
    with engine.connect() as conn:
        # First check if user exists
        email = "ryanhaley2000@gmail.com"
        result = conn.execute(text("SELECT id, email, username, password_hash, salt FROM users WHERE email = :email"), {"email": email})
        user = result.fetchone()
        
        if not user:
            print(f"User with email {email} NOT FOUND in production database!")
            print("\nLet's check what users exist...")
            result = conn.execute(text("SELECT id, email, username FROM users LIMIT 10"))
            users = result.fetchall()
            if users:
                print("Users in database:")
                for u in users:
                    print(f"  - ID: {u[0]}, Email: {u[1]}, Username: {u[2]}")
            else:
                print("No users found in database!")
        else:
            print(f"Found user: ID={user[0]}, Email={user[1]}, Username={user[2]}")
            print(f"Current password_hash exists: {bool(user[3])}")
            print(f"Current salt exists: {bool(user[4])}")
            
            # Generate new password
            new_password = "$paceMonkey2001!"
            new_salt = secrets.token_hex(32)
            new_hash = hash_password(new_password, new_salt)
            
            # Update password
            conn.execute(
                text("UPDATE users SET password_hash = :hash, salt = :salt WHERE email = :email"),
                {"hash": new_hash, "salt": new_salt, "email": email}
            )
            conn.commit()
            
            print(f"\nPassword reset successfully!")
            print(f"Email: {email}")
            print(f"New password: {new_password}")

except Exception as e:
    print(f"Error: {e}")
