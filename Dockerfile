FROM python:3.11-slim

# Evitar escritura de .pyc y buffer de salida
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Instalar dependencias del sistema mínimas
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias de Python
COPY pyproject.toml ./
RUN pip install --no-cache-dir build && \
    pip install --no-cache-dir .

# Copiar el código de la aplicación
COPY ./app ./app
COPY ./alembic ./alembic
COPY ./scratch ./scratch
COPY alembic.ini ./

# Crear carpetas necesarias
RUN mkdir -p /app/certs /app/cafs

CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
