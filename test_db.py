import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_connection():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        print("❌ DATABASE_URL is not set in your .env file.")
        sys.exit(1)
        
    print(f"Connecting to database: {db_url.split('@')[-1] if '@' in db_url else db_url}")
    
    try:
        from sqlalchemy import create_engine
        import models
        import database
        
        # Force table creation on the configured database
        models.Base.metadata.create_all(bind=database.engine)
        print("✅ Successfully connected to the database and initialized tables!")
        
        # Test session query
        db = database.SessionLocal()
        user_count = db.query(models.User).count()
        print(f"✅ Database session test passed. Current user count: {user_count}")
        db.close()
        
    except ImportError as ie:
        print(f"❌ Dependency import failure: {ie}. Make sure psycopg2 or psycopg2-binary is installed.")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        print("\nSuggestions:")
        print("1. If using Supabase or Neon, verify your connection URI is correct.")
        print("2. Ensure your local IP address is allowed in the cloud database firewall (allowed IP addresses / pg_hba).")

if __name__ == "__main__":
    test_connection()
