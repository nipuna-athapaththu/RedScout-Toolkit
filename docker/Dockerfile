FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    nmap whois dnsutils hydra git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install -e .

ENTRYPOINT ["python", "-m", "redscout.main"]
CMD ["--help"]