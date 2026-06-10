FROM python:3.12-slim
RUN pip install --no-cache-dir aiosmtpd requests
WORKDIR /app
COPY . .

# make Python unbuffered so prints show up immediately in docker logs
ENV PYTHONUNBUFFERED=1
CMD ["python", "bridge.py"]