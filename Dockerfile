FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FASTEMBED_CACHE_PATH=/models

WORKDIR /app
RUN apt-get update \
    && apt-get install --no-install-recommends -y git \
    && rm -rf /var/lib/apt/lists/*
RUN addgroup --system agent && adduser --system --ingroup agent agent
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --no-cache-dir .
RUN mkdir -p /models && chown -R agent:agent /app /models

USER agent
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
