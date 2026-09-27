from __future__ import annotations

from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware

from ra_xsoc_api.config import APISettings
from ra_xsoc_api.routes.analysis import router as analysis_router
from ra_xsoc_api.routes.cases import router as cases_router
from ra_xsoc_api.routes.reports import router as reports_router
from ra_xsoc_api.schemas import ErrorDetail, ErrorResponse

settings = APISettings.from_environment()

app = FastAPI(
    title="RA-XSOC Security Copilot API",
    version=settings.api_version,
    description="HTTP API for the RA-XSOC security operations copilot.",
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    request_id = getattr(
        request.state,
        "request_id",
        request.headers.get("X-Request-ID", str(uuid4())),
    )

    payload = ErrorResponse(
        error=ErrorDetail(
            code="VALIDATION_ERROR",
            message="Request validation failed.",
            details=exc.errors(),
        ),
        request_id=request_id,
    )

    return JSONResponse(
        status_code=422,
        content=payload.model_dump(mode="json"),
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:
    request_id = getattr(
        request.state,
        "request_id",
        request.headers.get("X-Request-ID", str(uuid4())),
    )

    message = (
        exc.detail
        if isinstance(exc.detail, str)
        else "HTTP request failed."
    )

    payload = ErrorResponse(
        error=ErrorDetail(
            code=f"HTTP_{exc.status_code}",
            message=message,
        ),
        request_id=request_id,
    )

    return JSONResponse(
        status_code=exc.status_code,
        content=payload.model_dump(mode="json"),
        headers=exc.headers,
    )

app.add_middleware(GZipMiddleware, minimum_size=1000)

if settings.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-Request-ID"],
    )


@app.middleware("http")
async def request_id_middleware(
    request: Request,
    call_next,
) -> Response:
    request_id = request.headers.get("X-Request-ID")

    if not request_id:
        request_id = str(uuid4())

    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    return response


app.include_router(analysis_router)
app.include_router(cases_router)
app.include_router(reports_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": settings.service_name,
    }


@app.get("/ready")
def readiness() -> dict[str, str]:
    return {
        "status": "ready",
        "service": settings.service_name,
    }