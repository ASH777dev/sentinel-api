from collections.abc import AsyncGenerator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


def _build_async_db_url(raw_url: str) -> tuple[str, dict]:
    url = raw_url.strip()
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

    parts = urlsplit(url)
    params = dict(parse_qsl(parts.query))
    needs_ssl = params.pop("sslmode", None) in {"require", "verify-ca", "verify-full"}
    params.pop("channel_binding", None)

    clean_url = urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(params), parts.fragment)
    )
    connect_args: dict = {"statement_cache_size": 0}
    if needs_ssl:
        connect_args["ssl"] = "require"
    return clean_url, connect_args


db_url, db_connect_args = _build_async_db_url(settings.database_url)

engine = create_async_engine(
    db_url,
    connect_args=db_connect_args,
    pool_pre_ping=True,
    pool_recycle=240,
    pool_size=5,
    max_overflow=10,
)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session