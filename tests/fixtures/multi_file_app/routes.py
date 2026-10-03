from .auth import require_auth
from .service import document_service

@require_auth
def fetch_user_document(document_id: str):
    """
    HTTP endpoint retrieving document details by document_id.
    Note: NO explicit IDOR or vulnerability docstring/label.
    """
    doc = document_service.get_document(document_id)
    return doc
