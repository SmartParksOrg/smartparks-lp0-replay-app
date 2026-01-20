FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DATA_DIR=/data
EXPOSE 18080

CMD ["gunicorn", "--bind", "0.0.0.0:18080", "--workers", "1", "--threads", "4", "wsgi:application"]
