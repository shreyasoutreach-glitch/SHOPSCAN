"""shopscan.rendered -- rendered-DOM verification interface and conservative default."""
CONFIRMED, NOT_REPRODUCED, ERROR, NOT_RUN = "CONFIRMED", "NOT_REPRODUCED", "ERROR", "NOT_RUN"

class RenderedVerifier:
    name = "base"
    def verify(self, url, findings):
        raise NotImplementedError

class NotRun(RenderedVerifier):
    name = "not_run"
    def verify(self, url, findings):
        return {(f["signature"], f["occurrence"]): NOT_RUN for f in findings}
