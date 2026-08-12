FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY app ./app
# scripts/ (e.g. backfill_anomaly_scores.py) needs the installed `app`
# package to import from -- included in the image so it's runnable via
# `docker exec <container> python -m scripts.backfill_anomaly_scores`
# against the real deployed environment, not just locally.
COPY scripts ./scripts
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
