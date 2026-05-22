import os
import shutil
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Use PostgreSQL by default, fallback to SQLite if DB_URL is missing
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./bids.db")

# Fix Heroku/Vercel Postgres URL which starts with postgres:// instead of postgresql://
if SQLALCHEMY_DATABASE_URL.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URL = SQLALCHEMY_DATABASE_URL.replace("postgres://", "postgresql://", 1)

# On Vercel (read-only filesystem), SQLite needs to write to /tmp
if os.getenv("VERCEL") and SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    if "sqlite:////" not in SQLALCHEMY_DATABASE_URL:
        db_file = SQLALCHEMY_DATABASE_URL.split("/")[-1]
        target_path = f"/tmp/{db_file}"
        source_path = os.path.abspath(db_file)
        
        # Copy file if source exists and target does not exist yet
        if os.path.exists(source_path) and not os.path.exists(target_path):
            try:
                shutil.copy2(source_path, target_path)
            except Exception as e:
                print(f"Error copying SQLite database to /tmp: {e}")
                
        SQLALCHEMY_DATABASE_URL = f"sqlite:///{target_path}"

if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

