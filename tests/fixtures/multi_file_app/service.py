from .repository import doc_repo

class DocumentService:
    def get_document(self, document_id: str):
        # Fetches document directly by ID from repository
        doc = doc_repo.find_by_id(document_id)
        return doc

document_service = DocumentService()
