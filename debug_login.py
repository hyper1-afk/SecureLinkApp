"""
Debug login issue
"""
import os

DATABASE_URL = "postgresql://dev-db-748382:AVNS_-_mAt6xfcsoj8ALfYam@app-f889963a-fcf6-4681-b928-7f70badeea57-do-user-32910661-0.e.db.ondigitalocean.com:25060/dev-db-748382?sslmode=require"
os.environ['DATABASE_URL'] = DATABASE_URL

from auth import AuthManager, User

auth = AuthManager()

# Test login directly
print("\n=== Testing Login ===\n")
result = auth.login(
    email_or_username="ryanhaley2000@gmail.com",
    password="$paceMonkey2001!"
)

print(f"Result: {result}")

# Also check if user exists and is active
session = auth.get_session()
user = session.query(User).filter(User.email == "ryanhaley2000@gmail.com").first()
if user:
    print(f"\nUser found:")
    print(f"  ID: {user.id}")
    print(f"  Username: {user.username}")
    print(f"  Email: {user.email}")
    print(f"  Is Active: {user.is_active}")
    print(f"  Has Password Hash: {bool(user.password_hash)}")
    print(f"  Has Salt: {bool(user.salt)}")
session.close()
