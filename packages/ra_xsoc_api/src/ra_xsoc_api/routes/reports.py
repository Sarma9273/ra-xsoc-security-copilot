from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from ra_xsoc_api.auth import AuthenticatedUser, require_roles
from ra_xsoc_api.dependencies import get_case_store
from ra_xsoc_api.reporting import render_html, render_pdf
from ra_xsoc_engine.domain.enums import UserRole

router = APIRouter(prefix="/api/v1/cases", tags=["reports"])

@router.get("/{analysis_id}/report.html", response_class=HTMLResponse)
def report(
    analysis_id: UUID,
    store=Depends(get_case_store),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.REVIEWER, UserRole.VIEWER)),
):
    case = store.get_analysis(analysis_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Analysis case not found.")
    return HTMLResponse(render_html(case), headers={"Content-Disposition": f'inline; filename="ra-xsoc-{analysis_id}.html"'})


@router.get("/{analysis_id}/report.pdf")
def pdf_report(
    analysis_id: UUID,
    store=Depends(get_case_store),
    user: AuthenticatedUser = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.REVIEWER, UserRole.VIEWER)),
):
    import tempfile
    from pathlib import Path
    case = store.get_analysis(analysis_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Analysis case not found.")
    with tempfile.TemporaryDirectory() as directory:
        path = render_pdf(case, Path(directory) / f"ra-xsoc-{analysis_id}.pdf")
        return Response(
            content=path.read_bytes(),
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="ra-xsoc-{analysis_id}.pdf"'},
        )
