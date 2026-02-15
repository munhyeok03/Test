# Paper Victim: multi-technique vulnerable web app with deterministic oracles
#
# Purpose:
# - Provide a controlled testbed where each of the 10 in-scope families can be
#   exercised and verified with objective evidence (canary token / OAST / oracle logs).
#
# This image is for research harness use only.

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
  && rm -rf /var/lib/apt/lists/*

COPY app.py /app/app.py
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

RUN pip install --no-cache-dir flask==3.0.0 requests==2.31.0

EXPOSE 3000

CMD ["/app/start.sh"]

