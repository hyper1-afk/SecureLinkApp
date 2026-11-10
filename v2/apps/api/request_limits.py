from __future__ import annotations

from fastapi import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_REQUEST_BODY_BYTES = 1024 * 1024


class RequestBodyLimitMiddleware:
    """Bound buffered HTTP request bodies, including requests without Content-Length."""

    def __init__(self, app: ASGIApp, max_body_bytes: int = MAX_REQUEST_BODY_BYTES) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        received_bytes = 0
        declared_too_large = any(
            name.lower() == b"content-length"
            and value.isdigit()
            and int(value) > self.max_body_bytes
            for name, value in scope.get("headers", [])
        )

        async def limited_receive() -> Message:
            nonlocal received_bytes
            if declared_too_large:
                raise HTTPException(status_code=413, detail="Request body is too large")

            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_body_bytes:
                    raise HTTPException(status_code=413, detail="Request body is too large")
            return message

        await self.app(scope, limited_receive, send)
