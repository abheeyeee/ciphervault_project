FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code
COPY . .

# Create the vaults directory
RUN mkdir -p vaults

# Expose port 8000
EXPOSE 8000

# Run the FastAPI server
CMD ["uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]
