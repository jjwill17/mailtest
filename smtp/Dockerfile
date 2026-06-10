FROM python:3.12-slim

# Disable Python stdout/stderr buffering for real-time Docker logs
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install aiosmtpd requests

COPY app.py .

EXPOSE 2525

CMD ["python", "app.py"]

