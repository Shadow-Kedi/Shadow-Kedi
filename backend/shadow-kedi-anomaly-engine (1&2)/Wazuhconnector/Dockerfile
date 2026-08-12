FROM python:3.12-slim

WORKDIR /app

COPY wazuh_connector.py ./
RUN pip install --no-cache-dir opensearch-py requests

CMD ["python", "wazuh_connector.py"]