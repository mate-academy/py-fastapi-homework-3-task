# Use a smaller base image for Python (slim version)
FROM python:3.10-slim

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=off
ENV ALEMBIC_CONFIG=/usr/src/alembic/alembic.ini
ENV PYTHONPATH=/usr/src/fastapi/src

# Install system dependencies
RUN apt update && apt install -y \
    gcc \
    libpq-dev \
    netcat-openbsd \
    postgresql-client \
    dos2unix \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*  # Clean up apt cache to reduce image size

# Install Poetry
RUN python -m pip install --upgrade pip && \
    pip install poetry

# Set working directory for Poetry and copy dependency files
WORKDIR /usr/src/poetry

COPY ./pyproject.toml /usr/src/poetry/pyproject.toml
COPY ./poetry.lock /usr/src/poetry/poetry.lock
COPY ./alembic.ini /usr/src/alembic/alembic.ini

# Configure Poetry to avoid creating a virtual environment inside the container
RUN poetry config virtualenvs.create false

# Install dependencies from Poetry (only main dependencies for production)
RUN poetry install --no-root --only main

# Set working directory for FastAPI
WORKDIR /usr/src/fastapi

# Copy FastAPI application source code
COPY ./src /usr/src/fastapi/src

# Copy custom shell commands (if any)
COPY ./commands /commands

# Ensure scripts have Unix line endings and make them executable
RUN dos2unix /commands/*.sh && chmod +x /commands/*.sh

# Expose port for the FastAPI application
EXPOSE 8000

# Default command to run FastAPI app using Uvicorn
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
