from contextlib import contextmanager


class Telemetry:
    """Phase 5 instrumentation port; SDK adapter is installed in Phase 6."""

    def __init__(self, console=False):
        self.console = console

    @contextmanager
    def span(self, name: str, **attributes):
        yield None

    def count(self, name: str, value: int = 1, **attributes):
        pass

    def observe(self, name: str, value: float, **attributes):
        pass

    def trace_id(self) -> str:
        return ""

    def shutdown(self):
        pass
