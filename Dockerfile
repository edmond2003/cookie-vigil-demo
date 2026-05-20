FROM python:3.11-slim

LABEL maintainer="CookieVigil Project"
LABEL description="CookieVigil - outil automatisé d'audit de sécurité des cookies web"

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

RUN mkdir -p reports \
    && groupadd -g 1000 cookievigil \
    && useradd -u 1000 -g cookievigil -m -s /usr/sbin/nologin cookievigil \
    && chown -R cookievigil:cookievigil /app

USER cookievigil

ENTRYPOINT ["python", "audit_cookies.py"]
