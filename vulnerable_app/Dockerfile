FROM python:3.11-slim

LABEL description="Application Flask volontairement vulnérable pour les démonstrations CookieVigil"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN groupadd -g 1000 vulnapp \
    && useradd -u 1000 -g vulnapp -m -s /usr/sbin/nologin vulnapp \
    && chown -R vulnapp:vulnapp /app

USER vulnapp

EXPOSE 5000

CMD ["python", "app.py"]
