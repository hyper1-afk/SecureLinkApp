"""
List all users in the database
"""
import os

DATABASE_URL = "postgresql://dev-db-748382:AVNS_-_mAt6xfcsoj8ALfYam@app-f889963a-fcf6-4681-b928-7f70badeea57-do-user-32910661-0.e.db.ondigitalocean.com:25060/dev-db-748382?sslmode=require"
os.environ['DATABASE_URL'] = DATABASE_URL

from auth import AuthManager, User

auth = AuthManager()
session = auth.get_session()

users = session.query(User).all()
print(f"\n=== Users in database ({len(users)} total) ===\n")
for user in users:
    print(f"  ID: {user.id}")
    print(f"  Username: {user.username}")
    print(f"  Email: {user.email}")
    print(f"  ---")

session.close()
