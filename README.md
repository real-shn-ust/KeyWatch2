# KeyWatch2

A Flask API for scanning and parsing certificates on remote Linux machines using Fabric and Celery for asynchronous processing.

## Features

- Asynchronous certificate scanning on remote machines
- Parses certificate details using cryptography library
- Extracts subject, issuer, validity dates, serial number, and signature algorithm
- API-only interface with task status checking
- Containerized with Docker Compose

## Setup

### Option 1: Local Development

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Start Redis (for Celery broker):
   ```
   redis-server
   ```

3. Start Celery worker:
   ```
   celery -A tasks worker --loglevel=info
   ```

4. Run the Flask app:
   ```
   python app.py
   ```

### Option 2: Docker Compose (Recommended)

1. Build and start all services:
   ```
   docker-compose up --build
   ```

   This will start:
   - Flask web app on port 5000
   - Redis on port 6379
   - Celery worker

2. Stop services:
   ```
   docker-compose down
   ```

## API Usage

### Start Scan
```
POST /scan
Content-Type: application/json

{
  "host": "example.com",
  "user": "myuser",
  "password": "mypass"
}
```
Returns: `{"task_id": "uuid"}` (202 status)

### Check Status
```
GET /status/<task_id>
```
Returns task status and results when complete.

## Requirements

- Docker and Docker Compose (for containerized deployment)
- SSH access to remote machine with password authentication
- Sudo access on remote machine for file discovery and reading