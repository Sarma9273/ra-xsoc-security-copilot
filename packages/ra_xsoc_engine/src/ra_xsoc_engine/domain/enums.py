from enum import Enum


class SeverityLevel(str, Enum):
    """Recommended severity of a security incident."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NoveltyStatus(str, Enum):
    """Whether an incident resembles known attack categories."""

    KNOWN = "known"
    POSSIBLY_NOVEL = "possibly_novel"
    UNKNOWN = "unknown"


class ReviewStatus(str, Enum):
    """Human-review state of an analysis result."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    CORRECTED = "corrected"
    REJECTED = "rejected"


class IncidentSource(str, Enum):
    """Origin of an incident submitted to RA-XSOC."""

    MANUAL = "manual"
    FILE_UPLOAD = "file_upload"
    SIEM = "siem"
    API = "api"
    DEMO = "demo"


class UserRole(str, Enum):
    """Planned RA-XSOC user roles."""

    ADMIN = "admin"
    ANALYST = "analyst"
    REVIEWER = "reviewer"
    VIEWER = "viewer"
