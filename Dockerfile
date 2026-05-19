FROM python:3.11-slim

LABEL maintainer="CookieVigil Project"
LABEL description="CookieVigil - Automated web cookie security auditor"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY audit_cookies.py .
COPY cookievigil.py .
COPY src ./src
COPY tests ./tests

RUN mkdir -p reports

ENTRYPOINT ["python", "audit_cookies.py"]
