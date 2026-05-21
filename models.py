from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from database import Base
import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class NetworkLog(Base):
    __tablename__ = "network_logs"

    id = Column(Integer, primary_key=True, index=True)
    tx_hash = Column(String, index=True, nullable=True)
    gas_used = Column(Float, nullable=True)
    value_eth = Column(Float, nullable=True)
    from_address = Column(String, nullable=True)
    to_address = Column(String, nullable=True)
    anomaly_score = Column(Float, default=0.0)
    severity = Column(String, default="Low Risk")
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Rich transaction metadata (IPS evolution)
    gas_fee_eth = Column(Float, nullable=True)
    wallet_age_days = Column(Integer, nullable=True)
    tx_frequency = Column(Integer, nullable=True)
    failed_tx_count = Column(Integer, nullable=True)
    permissions = Column(String, nullable=True)
    token_approval_amount = Column(Float, nullable=True)
    risk_score = Column(Integer, default=0)
    mempool_status = Column(String, default="confirmed")  # "pending", "confirmed", "blocked"

class ThreatEntity(Base):
    __tablename__ = "threat_entities"

    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String, index=True)  # "wallet", "contract", "domain"
    value = Column(String, unique=True, index=True)  # Address or domain name
    description = Column(String, nullable=True)
    severity = Column(String, default="Critical")  # "Critical", "High Risk", "Medium Risk"
    added_at = Column(DateTime, default=datetime.datetime.utcnow)

