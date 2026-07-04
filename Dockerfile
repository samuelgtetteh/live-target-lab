FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY identity_generator.py ics_generator.py ./
# Actual command is set per-service in docker-compose.yml
