# Blockchain Intrusion Detection System (BIDS) - Backend

This is the FastAPI backend for the Blockchain Intrusion Detection System. It features real-time Ethereum transaction monitoring, Scikit-learn AI anomaly detection (Isolation Forest), and live WebSocket alerts.

## 🚀 Tech Stack
- **FastAPI** (Async Python Web Framework)
- **PostgreSQL / SQLite** (Database via SQLAlchemy)
- **Web3.py** (Blockchain Interaction)
- **Scikit-learn** (Isolation Forest AI Model)
- **JWT** (Authentication)
- **WebSockets** (Real-time live alerts)

## 📁 Project Structure
- `main.py`: Entry point, REST API routes, WebSockets, and background blockchain monitor.
- `database.py`: SQLAlchemy database connection setup.
- `models.py`: Database table schemas (`User`, `NetworkLog`).
- `auth.py`: JWT token generation and password hashing.
- `blockchain_service.py`: Web3 integration to fetch blocks and extract transaction features.
- `ml_service.py`: Scikit-learn wrapper to load the AI model and predict anomalies.
- `create_dummy_model.py`: Script to generate a pre-trained `model.pkl`.

## 🛠️ Setup Instructions

### Option 1: Local Python Setup

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Environment Variables**:
   Copy `.env.example` to `.env` and update the values if you are using PostgreSQL or a specific Ethereum node (like Infura). By default, it will use a local SQLite database (`bids.db`) and look for a local Ethereum node on `http://127.0.0.1:8545`.

3. **Generate AI Model**:
   Generate the initial Isolation Forest model:
   ```bash
   python create_dummy_model.py
   ```

4. **Run the Server**:
   Start the FastAPI server:
   ```bash
   python -m uvicorn main:app --reload
   ```

5. **Test the APIs**:
   Open your browser and navigate to the interactive Swagger UI:
   `http://127.0.0.1:8000/docs`

### Option 2: Docker Setup

1. Build the Docker image:
   ```bash
   docker build -t bids-backend .
   ```

2. Run the Docker container:
   ```bash
   docker run -d -p 8000:8000 --env-file .env.example bids-backend
   ```

## 📡 WebSockets (Live Alerts)
Connect your frontend to `ws://127.0.0.1:8000/ws/alerts`. When the background monitor detects an anomalous transaction on the blockchain, it will push a JSON payload:
```json
{
    "type": "ALERT",
    "severity": "HIGH",
    "anomaly_score": 0.2314,
    "tx_hash": "0x123abc...",
    "message": "HIGH severity anomaly detected in block 104"
}
```
