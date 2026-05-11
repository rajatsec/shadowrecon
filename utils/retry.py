import asyncio
import logging
from typing import Callable, TypeVar, Any

logger = logging.getLogger("ShadowRecon")

T = TypeVar("T")


async def with_retry(
    coro_fn: Callable[[], Any],
    retries: int = 3,
    base_delay: float = 1.0,
    label: str = "",
) -> Any:
    """Retries an async callable with exponential backoff on failure."""
    for attempt in range(retries):
        try:
            return await coro_fn()
        except asyncio.TimeoutError:
            if attempt == retries - 1:
                logger.warning(f"{label} timed out after {retries} attempts")
                return None
            await asyncio.sleep(base_delay * (2 ** attempt))
        except Exception as e:
            if attempt == retries - 1:
                logger.warning(f"{label} failed after {retries} attempts: {e}")
                return None
            await asyncio.sleep(base_delay * (2 ** attempt))
    return None
