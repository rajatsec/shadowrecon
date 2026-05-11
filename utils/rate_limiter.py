import asyncio
import time


class AsyncRateLimiter:
    """Token bucket rate limiter for async code."""

    def __init__(self, rate: int, per: float = 1.0):
        self._rate = rate
        self._per = per
        self._tokens = float(rate)
        self._lock = asyncio.Lock()
        self._last = time.monotonic()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._rate, self._tokens + elapsed * (self._rate / self._per))
            self._last = now
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) * (self._per / self._rate)
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *_):
        pass
