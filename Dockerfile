FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade pip setuptools

WORKDIR /app

COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . /app/

COPY ./cloudflare.crt /etc/ssl/flask/cloudflare.crt
COPY ./cloudflare.key /etc/ssl/flask/cloudflare.key

RUN chmod 600 /etc/ssl/flask/cloudflare.*

ENV SSL_CERT_PATH=/etc/ssl/flask/cloudflare.crt
ENV SSL_KEY_PATH=/etc/ssl/flask/cloudflare.key

EXPOSE 443

CMD ["python3", "app.py"]
