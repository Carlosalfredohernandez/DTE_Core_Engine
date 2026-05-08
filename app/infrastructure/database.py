"""
DTE Core Engine — Configuración de Base de Datos (SQL Server).

Configuración de engine y sessions de SQLAlchemy de forma asíncrona.
"""

from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import get_settings

settings = get_settings()

# Creamos el motor asíncrono.
# aioodbc maneja la concurrencia a nivel de driver para SQL Server.
# isolation_level="AUTOCOMMIT" para evitar bloqueos innecesarios o
# puedes dejarlo por defecto si manejas explícitamente el commit.
engine = create_async_engine(
    settings.database_url,
    echo=(settings.log_level == "DEBUG"),
    future=True,
    pool_pre_ping=True,  # Verifica conexión antes de usar
    pool_recycle=3600,   # Recicla conexiones tras 1 hora
)

# Factory de sesiones asíncronas
async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency para inyectar la sesión de base de datos en los endpoints FastAPI.
    """
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()
