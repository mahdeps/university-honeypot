FROM python:3.12-slim

# Run as a non-root user — even a honeypot should contain its own blast radius.
RUN useradd --create-home --shell /usr/sbin/nologin potuser

WORKDIR /opt/honeypot
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
RUN mkdir -p logs && chown -R potuser:potuser /opt/honeypot

USER potuser
EXPOSE 8080

# gunicorn would be nicer for "production", but the Flask server keeps the lab
# simple and the console feed readable. Swap to gunicorn if you load-test it.
CMD ["python", "-m", "app.honeypot"]
