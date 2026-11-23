FROM python:3.11-slim

WORKDIR /app

# Copy dependency manifests first for layer caching
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install dependencies and package
RUN pip install --no-cache-dir .

ENTRYPOINT ["llm-judge"]
CMD ["--help"]
