FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
COPY audit_cookies.py .
COPY cookievigil.py .
ENTRYPOINT ["python", "audit_cookies.py"]
CMD ["--help"]
