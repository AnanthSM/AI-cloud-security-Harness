"""Bounded execution, called only after the runtime has authorized an action."""
import asyncio
import copy
import time
from collections import deque

from harness.errors import Conflict, HarnessError, Invalid
from harness.schemas import Risk
from harness.tools.gateway import MCPGateway
from harness.tools.registry import ToolRegistry


class ToolExecutionError(HarnessError):
    pass


class ToolTransportError(ToolExecutionError):
    """A transport failure classified as transient by a trusted adapter."""


class ToolUncertainOutcome(ToolExecutionError):
    """A write may have executed. Reconcile state before proposing another action."""


class ToolRateLimited(ToolExecutionError):
    pass


class ToolExecutor:
    def __init__(self, registry: ToolRegistry, gateway: MCPGateway, timeout_seconds: float = 10,
                 read_retries: int = 2, max_concurrency: int = 4,
                 requests_per_minute: int = 120):
        if timeout_seconds <= 0 or read_retries < 0 or max_concurrency < 1 or requests_per_minute < 1:
            raise Invalid("Invalid executor limits")
        self.registry = registry
        self.gateway = gateway
        self.timeout_seconds = timeout_seconds
        self.read_retries = read_retries
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._rate_lock = asyncio.Lock()
        self._starts: deque[float] = deque()
        self._requests_per_minute = requests_per_minute

    async def _reserve(self) -> None:
        async with self._rate_lock:
            now = time.monotonic()
            while self._starts and self._starts[0] <= now - 60:
                self._starts.popleft()
            if len(self._starts) >= self._requests_per_minute:
                raise ToolRateLimited("Tool request rate limit reached")
            self._starts.append(now)

    async def execute(self, name: str, arguments: dict) -> dict:
        tool = self.registry.resolve(name)
        snapshot = self.registry.validate(tool.input_schema, arguments)
        attempts = 1 + (self.read_retries if tool.risk == Risk.READ else 0)
        for attempt in range(attempts):
            async with self._semaphore:
                await self._reserve()
                try:
                    result = await asyncio.wait_for(
                        self.gateway.call(tool.model_copy(deep=True), copy.deepcopy(snapshot)),
                        timeout=self.timeout_seconds)
                    return self.registry.validate(tool.output_schema, result)
                except Conflict:
                    # A trusted adapter can prove that its conditional write did not happen.
                    raise
                except (TimeoutError, ToolTransportError):
                    if tool.risk != Risk.READ:
                        raise ToolUncertainOutcome(
                            "Write outcome is uncertain; reconcile resource state before retrying") from None
                    if attempt + 1 == attempts:
                        raise ToolExecutionError("Read tool transport failed after bounded retries") from None
                except asyncio.CancelledError:
                    # Cancellation must propagate. The approval layer keeps its execution claim,
                    # preventing an interrupted write from being replayed automatically.
                    raise
                except Exception as exc:
                    if tool.risk != Risk.READ:
                        raise ToolUncertainOutcome(
                            "Write outcome is uncertain; reconcile resource state before retrying") from None
                    if isinstance(exc, Invalid):
                        raise Invalid("Tool output failed registered schema validation") from None
                    raise ToolExecutionError("Tool execution failed") from None
            await asyncio.sleep(0.01 * (2 ** attempt))
        raise ToolExecutionError("Tool execution failed")
