#!/bin/bash
set -e

# Setup venv if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Setting up virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements-web.txt
else
    source venv/bin/activate
fi

echo "Starting CipherVault Web..."
python3 -m uvicorn web.main:app --host 127.0.0.1 --port 8000 --reload
