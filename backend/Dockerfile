FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 libyara10 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 drishti

WORKDIR /app
COPY pyproject.toml README.md ./
COPY drishti ./drishti
COPY scripts ./scripts
COPY evaluation ./evaluation
RUN pip install --upgrade pip && pip install .

RUN mkdir -p /quarantine /observations \
    && chown -R drishti:drishti /app /quarantine /observations \
    && chmod 700 /quarantine
USER drishti
EXPOSE 8000
CMD ["uvicorn", "drishti.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
