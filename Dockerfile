# Use an official lightweight Python image
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project files
COPY . .

# Expose the port for Cloud Run (default is 8080)
EXPOSE 8080

# FIX Bug 14: No HEALTHCHECK was defined. Cloud Run and orchestrators use this
# to know when the service is ready and to restart it if it becomes unhealthy.
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/_stcore/health || exit 1

# Cloud Run sets the PORT environment variable.
# Run Streamlit on that port.
CMD streamlit run dashboard/app.py --server.port="${PORT:-8080}" --server.address="0.0.0.0"
