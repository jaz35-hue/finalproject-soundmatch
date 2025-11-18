from app import db, app
from sqlalchemy import inspect
import os

with app.app_context():
    engine = db.get_engine()
    print('SQLAlchemy engine URL:', engine.url)
    print('Engine connect path (if sqlite):', engine.url.database)
    print('Absolute DB path according to engine:', os.path.abspath(engine.url.database) if engine.url.database else None)
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print('Tables according to SQLAlchemy inspector:', tables)
