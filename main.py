from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from contextlib import asynccontextmanager
import asyncio
import random
import os
import datetime

import models
import database
import auth
from ml_service import ml_service
from blockchain_service import blockchain_service
from contract_analyzer import contract_analyzer

# Create database tables
models.Base.metadata.create_all(bind=database.engine)

# Seed default threats if table is empty
def seed_threats():
    db = database.SessionLocal()
    try:
        if db.query(models.ThreatEntity).count() == 0:
            default_threats = [
                models.ThreatEntity(
                    entity_type="wallet", 
                    value="0xdeadbeef10101010101010101010101010dead10", 
                    description="Known Phishing Wallet - Ethereum Drainer Campaign", 
                    severity="Critical"
                ),
                models.ThreatEntity(
                    entity_type="wallet", 
                    value="0xscam77777777777777777777777777777777777", 
                    description="Exploiter Wallet - Reentrancy Drainage Origin", 
                    severity="Critical"
                ),
                models.ThreatEntity(
                    entity_type="contract", 
                    value="0xbadc0de111111111111111111111111111111111", 
                    description="Fake Airdrop Smart Contract - Access Privilege Bypass", 
                    severity="High Risk"
                ),
                models.ThreatEntity(
                    entity_type="domain", 
                    value="blockshield-verify.io", 
                    description="Phishing Domain - Fake MetaMask Wallet Verifier", 
                    severity="Critical"
                ),
                models.ThreatEntity(
                    entity_type="domain", 
                    value="uniswap-rewards-claim.org", 
                    description="Phishing Domain - Fake Reward Claiming DApp Portal", 
                    severity="Critical"
                )
            ]
            db.add_all(default_threats)
            db.commit()
            print("Threat database seeded successfully.")
    except Exception as e:
        print(f"Error seeding threats: {e}")
    finally:
        db.close()

seed_threats()

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

def compute_risk(anomaly_score: float) -> tuple[int, str]:
    if anomaly_score <= 0.0:
        # Low risk: 0 - 30
        risk_score = max(0, min(30, int(30 + anomaly_score * 100)))
        severity = "Low Risk"
    elif anomaly_score <= 0.05:
        # Medium risk: 31 - 60
        risk_score = int(31 + (anomaly_score / 0.05) * 29)
        severity = "Medium Risk"
    elif anomaly_score <= 0.15:
        # High risk: 61 - 85
        risk_score = int(61 + ((anomaly_score - 0.05) / 0.10) * 24)
        severity = "High Risk"
    else:
        # Critical risk: 86 - 100
        risk_score = min(100, int(86 + ((anomaly_score - 0.15) / 0.15) * 14))
        severity = "Critical"
    return risk_score, severity

# Background Monitoring Task
async def monitor_blockchain():
    print("Started background blockchain monitoring...")
    last_block = blockchain_service.get_latest_block_number()
    
    while True:
        try:
            current_block = blockchain_service.get_latest_block_number()
            if current_block and last_block and current_block > last_block:
                for block_num in range(last_block + 1, current_block + 1):
                    # Fetch transactions for new blocks
                    txs = blockchain_service.get_transactions_for_block(block_num)
                    for tx in txs:
                        # Check threat database reputation
                        db = database.SessionLocal()
                        is_threat = False
                        threat_desc = ""
                        threat_sev = "Critical"
                        try:
                            from_threat = db.query(models.ThreatEntity).filter(models.ThreatEntity.value == tx["from_address"]).first()
                            to_threat = db.query(models.ThreatEntity).filter(models.ThreatEntity.value == tx["to_address"]).first()
                            if from_threat:
                                is_threat = True
                                threat_desc = from_threat.description
                                threat_sev = from_threat.severity
                            elif to_threat:
                                is_threat = True
                                threat_desc = to_threat.description
                                threat_sev = to_threat.severity
                        finally:
                            db.close()
                            
                        anomaly_score = ml_service.predict_anomaly(
                            gas_used=tx["gas_used"],
                            value_eth=tx["value_eth"],
                            is_contract=tx["is_contract"],
                            tx_frequency=tx["tx_frequency"],
                            failed_tx_ratio=tx["failed_tx_ratio"]
                        )
                        
                        if is_threat:
                            if threat_sev == "Critical":
                                risk_score = random.randint(95, 100)
                                severity = "Critical"
                            elif threat_sev == "High Risk":
                                risk_score = random.randint(75, 94)
                                severity = "High Risk"
                            else:
                                risk_score = random.randint(50, 74)
                                severity = "Medium Risk"
                        else:
                            risk_score, severity = compute_risk(anomaly_score)
                                
                        # Save to DB (Requires opening a new session manually)
                        db = database.SessionLocal()
                        try:
                            new_log = models.NetworkLog(
                                tx_hash=tx["tx_hash"],
                                gas_used=tx["gas_used"],
                                value_eth=tx["value_eth"],
                                from_address=tx["from_address"],
                                to_address=tx["to_address"],
                                anomaly_score=anomaly_score,
                                severity=severity,
                                gas_fee_eth=tx["gas_fee_eth"],
                                wallet_age_days=tx["wallet_age_days"],
                                tx_frequency=tx["tx_frequency"],
                                failed_tx_count=tx["failed_tx_count"],
                                permissions=tx["permissions"],
                                token_approval_amount=tx["token_approval_amount"],
                                risk_score=risk_score,
                                mempool_status="confirmed"
                            )
                            db.add(new_log)
                            db.commit()
                            db.refresh(new_log)
                            
                            # Broadcast log details
                            timestamp_str = new_log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                            await manager.broadcast({
                                "type": "TRANSACTION",
                                "id": new_log.id,
                                "severity": severity,
                                "anomaly_score": round(anomaly_score, 4),
                                "risk_score": risk_score,
                                "tx_hash": tx["tx_hash"],
                                "gas_used": tx["gas_used"],
                                "gas_fee_eth": tx["gas_fee_eth"],
                                "value_eth": tx["value_eth"],
                                "from_address": tx["from_address"],
                                "to_address": tx["to_address"],
                                "wallet_age_days": tx["wallet_age_days"],
                                "failed_tx_count": tx["failed_tx_count"],
                                "permissions": tx["permissions"],
                                "token_approval_amount": tx["token_approval_amount"],
                                "mempool_status": "confirmed",
                                "timestamp": timestamp_str
                            })
                            
                            # If anomalous, broadcast alert as well
                            if severity in ["Medium Risk", "High Risk", "Critical"]:
                                await manager.broadcast({
                                    "type": "ALERT",
                                    "severity": severity,
                                    "anomaly_score": round(anomaly_score, 4),
                                    "risk_score": risk_score,
                                    "tx_hash": tx["tx_hash"],
                                    "message": f"{severity} severity anomaly detected in block {block_num}! Reason: {threat_desc or 'ML Outlier'}"
                                })
                        finally:
                            db.close()
                last_block = current_block
        except Exception as e:
            print(f"Error in monitor loop: {e}")
            
        await asyncio.sleep(10) # Poll every 10 seconds

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    print("Starting up BlockShield Backend...")
    task = asyncio.create_task(monitor_blockchain())
    yield
    # Shutdown actions
    print("Shutting down...")
    task.cancel()

app = FastAPI(title="BlockShield Intrusion Prevention System API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Pydantic models for request validation
class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class AnalyzeRequest(BaseModel):
    tx_hash: str

class ThreatCreate(BaseModel):
    entity_type: str
    value: str
    description: str
    severity: str = "Critical"

class PreCheckRequest(BaseModel):
    from_address: str
    to_address: str
    value_eth: float
    gas_used: float
    gas_price_gwei: float = 20.0
    token_approval_amount: float = 0.0
    permissions: str = "None"
    wallet_age_days: int = 100
    failed_tx_count: int = 0
    associated_domain: str = ""

class AnalyzeContractRequest(BaseModel):
    code: str

class ConfirmRequest(BaseModel):
    log_id: int

# Dependency to get current user
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    username = auth.verify_token(token)
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/api/auth/register", response_model=Token)
def register(user: UserCreate, db: Session = Depends(database.get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_pwd = auth.get_password_hash(user.password)
    new_user = models.User(username=user.username, hashed_password=hashed_pwd)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    access_token = auth.create_access_token(data={"sub": new_user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/v1/analyze")
def analyze_transaction(request: AnalyzeRequest, db: Session = Depends(database.get_db), current_user: models.User = Depends(get_current_user)):
    tx_data = blockchain_service.fetch_transaction_data(request.tx_hash)
    if not tx_data:
        raise HTTPException(status_code=404, detail="Transaction not found on blockchain")
    
    # Check reputation
    from_threat = db.query(models.ThreatEntity).filter(models.ThreatEntity.value == tx_data["from_address"]).first()
    to_threat = db.query(models.ThreatEntity).filter(models.ThreatEntity.value == tx_data["to_address"]).first()
    is_threat = from_threat or to_threat
    
    anomaly_score = ml_service.predict_anomaly(
        gas_used=tx_data["gas_used"],
        value_eth=tx_data["value_eth"],
        is_contract=tx_data["is_contract"],
        tx_frequency=tx_data["tx_frequency"],
        failed_tx_ratio=tx_data["failed_tx_ratio"]
    )
    
    if is_threat:
        severity = "Critical"
        risk_score = random.randint(95, 100)
    else:
        risk_score, severity = compute_risk(anomaly_score)
    
    # Save log to DB
    new_log = models.NetworkLog(
        tx_hash=tx_data["tx_hash"],
        gas_used=tx_data["gas_used"],
        value_eth=tx_data["value_eth"],
        from_address=tx_data["from_address"],
        to_address=tx_data["to_address"],
        anomaly_score=anomaly_score,
        severity=severity,
        gas_fee_eth=tx_data["gas_fee_eth"],
        wallet_age_days=tx_data["wallet_age_days"],
        tx_frequency=tx_data["tx_frequency"],
        failed_tx_count=tx_data["failed_tx_count"],
        permissions=tx_data["permissions"],
        token_approval_amount=tx_data["token_approval_amount"],
        risk_score=risk_score,
        mempool_status="confirmed"
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)
    
    return {
        "tx_hash": tx_data["tx_hash"],
        "risk_score": risk_score,
        "severity": severity,
        "anomaly_score": anomaly_score,
        "details": f"{severity} severity intrusion detected!" if risk_score > 30 else "Normal activity."
    }

@app.get("/api/transactions")
def get_transactions(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db), current_user: models.User = Depends(get_current_user)):
    return db.query(models.NetworkLog).order_by(models.NetworkLog.timestamp.desc()).offset(skip).limit(limit).all()

@app.get("/api/anomalies")
def get_anomalies(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db), current_user: models.User = Depends(get_current_user)):
    return db.query(models.NetworkLog).filter(models.NetworkLog.severity != "Low Risk").order_by(models.NetworkLog.timestamp.desc()).offset(skip).limit(limit).all()

@app.get("/api/wallet/{address}")
def get_wallet_activity(address: str, skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db), current_user: models.User = Depends(get_current_user)):
    return db.query(models.NetworkLog).filter(
        (models.NetworkLog.from_address == address) | (models.NetworkLog.to_address == address)
    ).order_by(models.NetworkLog.timestamp.desc()).offset(skip).limit(limit).all()

@app.get("/api/alerts")
def get_alerts(limit: int = 10, db: Session = Depends(database.get_db), current_user: models.User = Depends(get_current_user)):
    return db.query(models.NetworkLog).filter(models.NetworkLog.severity.in_(["High Risk", "Critical"])).order_by(models.NetworkLog.timestamp.desc()).limit(limit).all()

# Threat Reputation Database Admin Routes
@app.get("/api/v1/threats")
def get_threats(db: Session = Depends(database.get_db), current_user: models.User = Depends(get_current_user)):
    return db.query(models.ThreatEntity).order_by(models.ThreatEntity.added_at.desc()).all()

@app.post("/api/v1/threats")
def create_threat(threat: ThreatCreate, db: Session = Depends(database.get_db), current_user: models.User = Depends(get_current_user)):
    existing = db.query(models.ThreatEntity).filter(models.ThreatEntity.value == threat.value).first()
    if existing:
        raise HTTPException(status_code=400, detail="Threat entity value already registered")
    
    new_threat = models.ThreatEntity(
        entity_type=threat.entity_type,
        value=threat.value,
        description=threat.description,
        severity=threat.severity
    )
    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)
    return new_threat

# Wallet Pre-signature Verification Middleware
@app.post("/api/v1/ips/pre-check")
async def pre_check_transaction(request: PreCheckRequest, db: Session = Depends(database.get_db), current_user: models.User = Depends(get_current_user)):
    # 1. Reputation Check
    from_threat = db.query(models.ThreatEntity).filter(models.ThreatEntity.value == request.from_address).first()
    to_threat = db.query(models.ThreatEntity).filter(models.ThreatEntity.value == request.to_address).first()
    domain_threat = None
    if request.associated_domain:
        domain_threat = db.query(models.ThreatEntity).filter(models.ThreatEntity.value == request.associated_domain).first()
        
    is_reputation_violation = from_threat or to_threat or domain_threat
    
    # 2. ML Check
    is_contract = 1 if request.permissions != "None" or request.token_approval_amount > 0 else 0
    tx_frequency = 1
    failed_tx_ratio = float(request.failed_tx_count) / 10.0 if request.failed_tx_count > 0 else 0.0
    
    anomaly_score = ml_service.predict_anomaly(
        gas_used=request.gas_used,
        value_eth=request.value_eth,
        is_contract=is_contract,
        tx_frequency=tx_frequency,
        failed_tx_ratio=failed_tx_ratio
    )
    
    # Determine risk score and severity
    if is_reputation_violation:
        severity = "Critical"
        risk_score = random.randint(95, 100)
        reason = "Known Scam Wallet Address" if (from_threat or to_threat) else f"Associated with Phishing Domain: {request.associated_domain}"
        action = "BLOCK"
    else:
        risk_score, severity = compute_risk(anomaly_score)
        reason = "ML Anomaly Score elevated" if risk_score > 30 else "Normal transaction signature metrics"
        action = "SAFE"
        
        # Heuristics override
        if request.token_approval_amount >= 1000000.0:
            severity = "Critical"
            risk_score = 98
            reason = f"Excessive Token Approval Request ({request.token_approval_amount:,} tokens) - High Drain Risk"
            action = "BLOCK"
        elif request.wallet_age_days <= 1:
            severity = "High Risk"
            risk_score = 82
            reason = "Interaction from newly deployed/created wallet (Age < 2 days)"
            action = "WARNING"
        elif request.gas_used > 5000000:
            severity = "High Risk"
            risk_score = 78
            reason = f"Extreme gas limit requested ({request.gas_used:,}) - Smart Contract Exploitation Warning"
            action = "WARNING"
            
    # Save validation logs as a blocked or pending record in the database
    gas_price_eth = (request.gas_price_gwei * 1e-9)
    gas_fee_eth = (request.gas_used * gas_price_eth)
    tx_hash = "0x" + "".join(random.choices("0123456789abcdef", k=64))
    
    new_log = models.NetworkLog(
        tx_hash=tx_hash,
        gas_used=request.gas_used,
        value_eth=request.value_eth,
        from_address=request.from_address,
        to_address=request.to_address,
        anomaly_score=anomaly_score,
        severity=severity,
        gas_fee_eth=gas_fee_eth,
        wallet_age_days=request.wallet_age_days,
        tx_frequency=tx_frequency,
        failed_tx_count=request.failed_tx_count,
        permissions=request.permissions,
        token_approval_amount=request.token_approval_amount,
        risk_score=risk_score,
        mempool_status="blocked" if action == "BLOCK" else "pending"
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)
    
    timestamp_str = new_log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    
    # Broadcast to dashboard
    await manager.broadcast({
        "type": "TRANSACTION",
        "id": new_log.id,
        "severity": severity,
        "anomaly_score": round(anomaly_score, 4),
        "risk_score": risk_score,
        "tx_hash": tx_hash,
        "gas_used": request.gas_used,
        "gas_fee_eth": gas_fee_eth,
        "value_eth": request.value_eth,
        "from_address": request.from_address,
        "to_address": request.to_address,
        "wallet_age_days": request.wallet_age_days,
        "failed_tx_count": request.failed_tx_count,
        "permissions": request.permissions,
        "token_approval_amount": request.token_approval_amount,
        "mempool_status": "blocked" if action == "BLOCK" else "pending",
        "timestamp": timestamp_str
    })
    
    if action == "BLOCK" or severity in ["High Risk", "Critical"]:
        await manager.broadcast({
            "type": "ALERT",
            "severity": severity,
            "anomaly_score": round(anomaly_score, 4),
            "risk_score": risk_score,
            "tx_hash": tx_hash,
            "message": f"IPS Wallet Interceptor triggered: {action} transaction! Reason: {reason}"
        })
        
    return {
        "status": "success",
        "log_id": new_log.id,
        "action": action,
        "severity": severity,
        "risk_score": risk_score,
        "reason": reason,
        "tx_hash": tx_hash
    }

# Wallet Confirmation Endpoint
@app.post("/api/v1/ips/confirm")
async def confirm_transaction(request: ConfirmRequest, db: Session = Depends(database.get_db), current_user: models.User = Depends(get_current_user)):
    log_entry = db.query(models.NetworkLog).filter(models.NetworkLog.id == request.log_id).first()
    if not log_entry:
        raise HTTPException(status_code=404, detail="Transaction log not found")
    
    if log_entry.mempool_status == "pending":
        log_entry.mempool_status = "confirmed"
        db.commit()
        db.refresh(log_entry)
        
        # Broadcast confirm update
        await manager.broadcast({
            "type": "TRANSACTION_UPDATE",
            "id": log_entry.id,
            "mempool_status": "confirmed",
            "tx_hash": log_entry.tx_hash
        })
        
        return {"status": "success", "message": "Transaction signed and confirmed."}
    else:
        return {"status": "error", "message": f"Transaction is not pending. Current status: {log_entry.mempool_status}"}

# Smart Contract Analysis Endpoint
@app.post("/api/v1/ips/analyze-contract")
def analyze_contract(request: AnalyzeContractRequest, current_user: models.User = Depends(get_current_user)):
    findings = contract_analyzer.analyze_solidity(request.code)
    return {
        "status": "success",
        "findings": findings,
        "summary": {
            "total": len(findings),
            "critical": len([f for f in findings if f["severity"] == "Critical"]),
            "high": len([f for f in findings if f["severity"] == "High Risk"]),
            "medium": len([f for f in findings if f["severity"] == "Medium Risk"])
        }
    }

@app.get("/api/v1/blockchain/accounts")
def get_blockchain_accounts(current_user: models.User = Depends(get_current_user)):
    try:
        if blockchain_service.is_connected():
            accounts = blockchain_service.w3.eth.accounts
            return {"status": "success", "accounts": accounts}
        return {"status": "error", "message": "Blockchain not connected", "accounts": []}
    except Exception as e:
        return {"status": "error", "message": str(e), "accounts": []}

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We are just listening to keep the connection alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Transaction Simulator Endpoint
class SimulateResponse(BaseModel):
    status: str
    transactions_generated: int

@app.post("/api/v1/simulate", response_model=SimulateResponse)
async def simulate_transactions(count: int = 5, db: Session = Depends(database.get_db), current_user: models.User = Depends(get_current_user)):
    generated = 0
    threats = db.query(models.ThreatEntity).all()
    threat_addresses = [t.value for t in threats if t.entity_type in ["wallet", "contract"]]
    
    for _ in range(count):
        is_anomaly = random.random() < 0.35
        
        from_address = "0x" + "".join(random.choices("0123456789abcdef", k=40))
        to_address = "0x" + "".join(random.choices("0123456789abcdef", k=40))
        tx_hash = "0x" + "".join(random.choices("0123456789abcdef", k=64))
        
        permissions = "None"
        token_approval_amount = 0.0
        wallet_age_days = random.randint(10, 1000)
        failed_tx_count = random.randint(0, 1)
        
        if is_anomaly:
            anomaly_type = random.choice([1, 2, 3, 4])
            if anomaly_type == 1 and threat_addresses:
                to_address = random.choice(threat_addresses)
                gas_used = float(random.randint(21000, 150000))
                value_eth = float(random.uniform(0.1, 5.0))
            elif anomaly_type == 2:
                permissions = "Unlimited Approval"
                token_approval_amount = float(random.choice([1000000, 5000000, 100000000]))
                gas_used = float(random.randint(60000, 120000))
                value_eth = 0.0
            elif anomaly_type == 3:
                gas_used = float(random.randint(21000, 80000))
                value_eth = float(random.uniform(0.5, 3.0))
                wallet_age_days = 0 # brand new
                failed_tx_count = random.randint(1, 3)
            else:
                gas_used = float(random.randint(6000000, 8000000))
                value_eth = float(random.uniform(10.0, 50.0))
                failed_tx_count = random.randint(5, 12)
        else:
            gas_used = float(random.randint(21000, 150000))
            value_eth = float(random.uniform(0.001, 1.5))
            if random.random() < 0.15:
                permissions = "Limited Approval"
                token_approval_amount = float(random.randint(5, 500))
                
        is_threat = (from_address in threat_addresses) or (to_address in threat_addresses)
        is_contract = 1 if permissions != "None" or token_approval_amount > 0.0 else 0
        tx_frequency = random.randint(5, 50) if is_anomaly else random.randint(1, 4)
        failed_tx_ratio = min(1.0, float(failed_tx_count) / 10.0)
        
        anomaly_score = ml_service.predict_anomaly(
            gas_used=gas_used,
            value_eth=value_eth,
            is_contract=is_contract,
            tx_frequency=tx_frequency,
            failed_tx_ratio=failed_tx_ratio
        )
        
        if is_threat:
            risk_score = random.randint(95, 100)
            severity = "Critical"
            reason = "Destination address matches blacklisted Threat Registry"
            action = "BLOCK"
        else:
            risk_score, severity = compute_risk(anomaly_score)
            reason = "Elevated Isolation Forest anomaly score" if risk_score > 30 else "Standard Transaction Check Passed"
            action = "SAFE"
            
            # Heuristics override
            if token_approval_amount >= 1000000.0:
                severity = "Critical"
                risk_score = 99
                reason = "Unlimited contract authorization - high draining probability"
                action = "BLOCK"
            elif wallet_age_days <= 1:
                severity = "High Risk"
                risk_score = 85
                reason = "Newly created sender wallet with high transaction velocity"
                action = "WARNING"
            elif gas_used > 5000000:
                severity = "High Risk"
                risk_score = 79
                reason = "Unusually high gas limit - transaction execution warnings"
                action = "WARNING"
                
        # Compute gas fee
        gas_price = random.uniform(15, 120) * 1e-9
        gas_fee_eth = gas_used * gas_price
        
        mempool_status = "blocked" if action == "BLOCK" else "pending"
        
        # Save to DB
        new_log = models.NetworkLog(
            tx_hash=tx_hash,
            gas_used=gas_used,
            value_eth=value_eth,
            from_address=from_address,
            to_address=to_address,
            anomaly_score=anomaly_score,
            severity=severity,
            gas_fee_eth=gas_fee_eth,
            wallet_age_days=wallet_age_days,
            tx_frequency=tx_frequency,
            failed_tx_count=failed_tx_count,
            permissions=permissions,
            token_approval_amount=token_approval_amount,
            risk_score=risk_score,
            mempool_status=mempool_status
        )
        db.add(new_log)
        db.commit()
        db.refresh(new_log)
        
        timestamp_str = new_log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        
        # Broadcast initial transaction
        await manager.broadcast({
            "type": "TRANSACTION",
            "id": new_log.id,
            "severity": severity,
            "anomaly_score": round(anomaly_score, 4),
            "risk_score": risk_score,
            "tx_hash": tx_hash,
            "gas_used": gas_used,
            "gas_fee_eth": gas_fee_eth,
            "value_eth": value_eth,
            "from_address": from_address,
            "to_address": to_address,
            "wallet_age_days": wallet_age_days,
            "failed_tx_count": failed_tx_count,
            "permissions": permissions,
            "token_approval_amount": token_approval_amount,
            "mempool_status": mempool_status,
            "timestamp": timestamp_str
        })
        
        if action == "BLOCK" or severity in ["High Risk", "Critical"]:
            await manager.broadcast({
                "type": "ALERT",
                "severity": severity,
                "anomaly_score": round(anomaly_score, 4),
                "risk_score": risk_score,
                "tx_hash": tx_hash,
                "message": f"IPS Gateway Blocked: {action}! Reason: {reason}"
            })
            
        if action != "BLOCK":
            await asyncio.sleep(1.2)
            
            # Confirm transaction
            db_session = database.SessionLocal()
            try:
                confirmed_log = db_session.query(models.NetworkLog).filter(models.NetworkLog.id == new_log.id).first()
                if confirmed_log:
                    confirmed_log.mempool_status = "confirmed"
                    db_session.commit()
            finally:
                db_session.close()
                
            await manager.broadcast({
                "type": "TRANSACTION_UPDATE",
                "id": new_log.id,
                "mempool_status": "confirmed",
                "tx_hash": tx_hash
            })
            
        generated += 1
        await asyncio.sleep(0.1) # Small delay
        
    return {"status": "success", "transactions_generated": generated}

# REST APIs for threat management connected to local DB & Ganache Blockchain

@app.post("/add-threat")
def add_threat_route(threat: ThreatCreate, db: Session = Depends(database.get_db)):
    """
    Logs a new threat entity locally in the database and stores it on the Ganache blockchain.
    """
    existing = db.query(models.ThreatEntity).filter(models.ThreatEntity.value == threat.value).first()
    if existing:
        raise HTTPException(status_code=400, detail="Threat entity value already registered locally.")
    
    new_threat = models.ThreatEntity(
        entity_type=threat.entity_type,
        value=threat.value,
        description=threat.description,
        severity=threat.severity
    )
    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)
    
    blockchain_tx = None
    blockchain_status = "unattempted"
    blockchain_error = None
    
    try:
        receipt = blockchain_service.store_threat_log_on_blockchain(
            entity_type=threat.entity_type,
            value=threat.value,
            description=threat.description,
            severity=threat.severity
        )
        blockchain_tx = receipt.get("tx_hash")
        blockchain_status = "success"
    except Exception as e:
        blockchain_status = "failed"
        blockchain_error = str(e)
        print(f"Failed to log threat on-chain: {e}")
        
    return {
        "status": "success" if blockchain_status == "success" else "partial_success",
        "message": "Threat logged locally and on blockchain successfully." if blockchain_status == "success" else "Threat logged locally, but blockchain write failed.",
        "local_data": {
            "id": new_threat.id,
            "entity_type": new_threat.entity_type,
            "value": new_threat.value,
            "severity": new_threat.severity
        },
        "blockchain": {
            "status": blockchain_status,
            "tx_hash": blockchain_tx,
            "error": blockchain_error
        }
    }

@app.get("/threats")
def get_all_threats_route(db: Session = Depends(database.get_db)):
    """
    Fetches all registered threats. Attempts to fetch from the Ganache blockchain first,
    falling back to the local database registry if needed.
    """
    try:
        onchain_threats = blockchain_service.fetch_threat_logs_from_blockchain()
        if onchain_threats:
            return {
                "source": "blockchain",
                "count": len(onchain_threats),
                "threats": onchain_threats
            }
    except Exception as e:
        print(f"Fallback to database due to blockchain read error: {e}")
        
    local_threats = db.query(models.ThreatEntity).order_by(models.ThreatEntity.added_at.desc()).all()
    formatted_local = [
        {
            "id": t.id,
            "entity_type": t.entity_type,
            "value": t.value,
            "description": t.description,
            "severity": t.severity,
            "timestamp": int(t.added_at.timestamp()) if t.added_at else None,
            "reporter": "database_fallback"
        }
        for t in local_threats
    ]
    return {
        "source": "database",
        "count": len(formatted_local),
        "threats": formatted_local
    }

@app.get("/verify/{id}")
def verify_threat_route(id: int, value: str):
    """
    Verifies that a threat record exists on the Ganache blockchain for the given ID
    and that its value matches the provided value parameter.
    """
    if not value:
        raise HTTPException(status_code=400, detail="Missing required query parameter: 'value'")
        
    try:
        is_verified = blockchain_service.verify_threat_record_on_blockchain(id, value)
        return {
            "id": id,
            "value": value,
            "verified": is_verified,
            "message": "Threat record verified on-chain." if is_verified else "Verification failed. Threat value mismatch or ID out of range."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"On-chain verification failed: {e}")

# Create static folder and serve frontend
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=FileResponse)
def read_root():
    return FileResponse("static/index.html")
