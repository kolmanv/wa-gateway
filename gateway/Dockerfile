FROM python:3.13-slim-trixie
WORKDIR /app
COPY requirements*.txt ./
RUN pip install --no-cache-dir -r $(ls requirements.lock 2>/dev/null || echo requirements.txt)
COPY app.py .
USER 10001
CMD ["python", "app.py"]
