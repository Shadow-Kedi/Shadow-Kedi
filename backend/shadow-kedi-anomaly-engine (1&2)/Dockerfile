FROM python:3.12-slim
WORKDIR /app
# JSON-array form required for these three -- shell-form COPY's tokenizer
# chokes on the "&" inside this directory's own name ("unexpected end of
# statement while looking for matching double-quote"), confirmed directly
# by reproducing it in isolation. JSON-array form parses as plain JSON
# strings instead, so the "&"/"("/")" are just literal characters.
COPY ["backend/shadow-kedi-anomaly-engine (1&2)/pyproject.toml", "./"]
COPY ["backend/shadow-kedi-anomaly-engine (1&2)/app", "./app"]
# scripts/ (e.g. backfill_anomaly_scores.py) needs the installed `app`
# package to import from -- included in the image so it's runnable via
# `docker exec <container> python -m scripts.backfill_anomaly_scores`
# against the real deployed environment, not just locally.
COPY ["backend/shadow-kedi-anomaly-engine (1&2)/scripts", "./scripts"]
# ML pipeline bridge (app/ml_scoring.py) needs these -- they live at the
# repo root, not under this service's own directory, hence context: ../..
# in docker-compose.yml instead of the default ".".
COPY pipeline ./pipeline
COPY shadow_kedi_adapter.py ./
# ml_scoring.py's own path-detection heuristic assumes a host-checkout
# layout (app/ -> engine dir -> backend/ -> repo root, 3 levels up) that
# doesn't exist inside this image (WORKDIR is flat: /app, /app/app,
# /app/pipeline) -- override explicitly rather than let it guess wrong.
ENV SHADOW_KEDI_PIPELINE_ROOT=/app
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
