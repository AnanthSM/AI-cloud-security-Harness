import hmac
import os

from fastapi import Header

from harness.errors import Forbidden
from harness.schemas import Principal


class TokenAuth:
    """Local bearer authentication. OIDC/JWT principal resolution replaces this in production."""

    def __init__(self):
        self.operator = os.environ.get("HARNESS_OPERATOR_TOKEN", "")
        self.reviewer = os.environ.get("HARNESS_REVIEWER_TOKEN", "")
        if self.operator and self.reviewer and hmac.compare_digest(self.operator, self.reviewer):
            raise Forbidden("Operator and reviewer credentials must differ")
        if any(token and len(token) < 32 for token in [self.operator, self.reviewer]):
            raise Forbidden("Configured API credentials must contain at least 32 characters")

    def principal(self, authorization: str | None = Header(default=None)) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise Forbidden("A configured bearer credential is required")
        token = authorization[7:]
        if self.reviewer and hmac.compare_digest(token, self.reviewer):
            return Principal(user_id="api-reviewer", role="reviewer")
        if self.operator and hmac.compare_digest(token, self.operator):
            return Principal(user_id="api-operator", role="operator")
        raise Forbidden("Invalid bearer credential")

    def require_reviewer(self, principal: Principal):
        if principal.role != "reviewer":
            raise Forbidden("A human reviewer credential is required")
