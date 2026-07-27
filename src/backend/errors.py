"""Uniform error contract: every failure returns {"error": {type, message}}.

Register `install_error_handlers(app)` once on the FastAPI app. Business code
raises `APIError(status, type, message)`; validation and unexpected errors are
normalized to the same envelope.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class APIError(Exception):
    def __init__(self, status_code: int, type: str, message: str) -> None:
        self.status_code = status_code
        self.type = type
        self.message = message
        super().__init__(message)


def _envelope(status_code: int, type: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code, content={"error": {"type": type, "message": message}}
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(APIError)
    async def _api_error(_: Request, exc: APIError) -> JSONResponse:
        return _envelope(exc.status_code, exc.type, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        return _envelope(400, "invalid_request", str(exc.errors()))

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _envelope(exc.status_code, "http_error", str(exc.detail))

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception) -> JSONResponse:
        return _envelope(500, "internal_error", "an unexpected error occurred")
