class RAXSOCError(Exception):
    """Base exception for RA-XSOC domain errors."""


class DomainValidationError(RAXSOCError):
    """Raised when a domain object receives invalid data."""


class KnowledgeBaseError(RAXSOCError):
    """Raised when knowledge-base content cannot be used safely."""


class RetrievalError(RAXSOCError):
    """Raised when semantic retrieval fails."""


class AnalysisError(RAXSOCError):
    """Raised when an incident cannot be analysed."""
