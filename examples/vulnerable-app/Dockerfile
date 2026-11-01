FROM python:latest

# Running as root without USER instruction
ENV API_KEY=DEMO_NOT_A_REAL_API_KEY
ENV DB_PASSWORD=DEMO_NOT_A_REAL_PASSWORD

# Dangerous command & remote download piping to shell
RUN apt-get update && apt-get install -y net-tools telnet curl \
    && curl -fsSL https://example.com/install.sh | bash \
    && chmod 777 /app

ADD ./src /app
WORKDIR /app

CMD ["python", "app.py"]
