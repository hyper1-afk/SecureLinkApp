"""
Shared database engine configuration
Ensures all database connections use the same engine and proper PostgreSQL in production.
"""
import os
from sqlalchemy import create_engine
from config import Config

_shared_engine = None

def get_database_engine(config: Config = None):
    """Get the shared database engine, creating it if necessary"""
    global _shared_engine
    
    if _shared_engine is not None:
        return _shared_engine
    
    if config is None:
        config = Config()
    
    # Use PostgreSQL if DATABASE_URL is set, otherwise fall back to SQLite
    if config.DATABASE_URL:
        db_url = config.DATABASE_URL
        # Handle postgres:// vs postgresql:// URL format
        if db_url.startswith('postgres://'):
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
        _shared_engine = create_engine(db_url, pool_pre_ping=True)
    else:
        _shared_engine = create_engine(f'sqlite:///{config.DATABASE_PATH}')
    
    return _shared_engine


def safe_create_tables(base_metadata, engine):
    """Safely create tables, handling 'already exists' errors"""
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
