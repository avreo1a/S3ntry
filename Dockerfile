FROM python:3.12.4-slim


WORKDIR /app


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


COPY . .


COPY scanner/ ./scanner/
COPY notify/ ./notify/


ENV PYTHONPATH=/app


CMD ["python", "app.py"]