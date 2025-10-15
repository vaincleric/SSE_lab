FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create secrets dir for local KMS
RUN mkdir -p /secrets && \
    chown root:root /secrets && \
    chmod 700 /secrets

ENV LOCAL_KEK_PATH=/secrets/kek

EXPOSE 5000

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "app:app"]
