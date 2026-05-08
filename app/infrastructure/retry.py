"""
DTE Core Engine — Utilidades para reintentos (Retry / Backoff).
"""

from typing import Any, Callable

import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.config import get_settings
from app.domain.exceptions import SiiAuthError, SiiEnvioError, SiiQueryError

logger = structlog.get_logger(__name__)

settings = get_settings()


def log_retry_attempt(retry_state: Any) -> None:
    """Loguea los intentos fallidos antes de reintentar."""
    if retry_state.outcome.failed:
        exception = retry_state.outcome.exception()
        logger.warning(
            "Reintentando operación SII",
            attempt=retry_state.attempt_number,
            exception_type=type(exception).__name__,
            error=str(exception),
        )


def sii_retry(func: Callable) -> Callable:
    """
    Decorador para llamadas al SII con backoff exponencial.
    Reintenta ante excepciones de autenticación, envío o consulta.
    """
    return retry(
        stop=stop_after_attempt(settings.sii_max_retries),
        wait=wait_exponential(
            multiplier=settings.sii_retry_delay_seconds, min=2, max=10
        ),
        retry=retry_if_exception_type(
            (SiiAuthError, SiiEnvioError, SiiQueryError, TimeoutError, ConnectionError)
        ),
        after=log_retry_attempt,
        reraise=True,
    )(func)
