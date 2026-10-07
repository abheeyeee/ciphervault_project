FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements-web.txt .
RUN pip install --no-cache-dir -r requirements-web.txt

# Ship only the stateless server and the two browser pages.
COPY web/main.py web/main.py
COPY web/static/landing.html web/static/landing.html
COPY web/static/vault.html web/static/vault.html
COPY web/static/assets web/static/assets

# Run the read-only application without root privileges.
USER 10001:10001

# Expose port 8000
EXPOSE 8000

# Run the FastAPI server
CMD ["uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]
