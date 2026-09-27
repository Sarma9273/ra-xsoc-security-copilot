from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from ra_xsoc_api.auth import AuthenticatedUser, require_roles
from ra_xsoc_api.dependencies import get_case_store
from ra_xsoc_api.reporting import render_html
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
