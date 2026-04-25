FROM python:3.11-slim

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY src/ src/
COPY config.yaml .

# Install the package
RUN pip install --no-cache-dir .

RUN pip install debugpy

# Download spaCy models (sm = lightweight fallback, lg = full NER)
RUN python -m spacy download en_core_web_sm && \
    python -m spacy download en_core_web_lg && \
    python -m spacy download sv_core_news_lg

EXPOSE 8080

CMD ["python", "-m", "debugpy", "--listen", "0.0.0.0:5678", \
     "-m", "swedsec_sanitizer"]
