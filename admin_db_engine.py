"""
Admin Database Engine - Separate from frontend user database
This ensures admin/employee data is completely isolated from user data.
"""
import os
from sqlalchemy import create_engine
from config import Config

_admin_engine = None

def get_admin_database_engine(config: Config = None):
    """Get the admin database engine (separate from user database)"""
    global _admin_engine
    
    if _admin_engine is not None:
        return _admin_engine
    
    if config is None:
        config = Config()
    
    # Use separate ADMIN_DATABASE_URL if set, otherwise use a separate SQLite file
    admin_db_url = os.getenv('ADMIN_DATABASE_URL')
    
    if admin_db_url:
        # Handle postgres:// vs postgresql:// URL format
        if admin_db_url.startswith('postgres://'):
            admin_db_url = admin_db_url.replace('postgres://', 'postgresql://', 1)
        _admin_engine = create_engine(admin_db_url, pool_pre_ping=True)
    else:
        # Use separate SQLite file for admin data locally
        admin_db_path = os.getenv('ADMIN_DATABASE_PATH', 'admin_database.db')
        _admin_engine = create_engine(f'sqlite:///{admin_db_path}')
    
    return _admin_engine


def safe_create_admin_tables(base_metadata, engine):
    """Safely create admin tables, handling 'already exists' errors"""
    from sqlalchemy import inspect
    
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()
    
    # Only create tables that don't exist
    for table in base_metadata.sorted_tables:
        if table.name not in existing_tables:
            try:
                table.create(engine, checkfirst=True)
            except Exception:
                pass  # Table already exists or other issue - continue
