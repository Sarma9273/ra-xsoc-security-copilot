from fastapi import FastAPI

from ra_xsoc_api.routes.analysis import router as analysis_router


app = FastAPI(
    title="RA-XSOC Security Copilot API",
    version="0.1.0",
    description="HTTP API for the RA-XSOC security operations copilot.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "ra-xsoc-api",
    }


app.include_router(analysis_router)