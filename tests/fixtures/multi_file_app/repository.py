class DocumentRepository:
    def __init__(self):
        self._db = {
            "doc_99": {"id": "doc_99", "owner_id": "usr_100", "title": "Private Notes"},
            "doc_100": {"id": "doc_100", "owner_id": "usr_200", "title": "Confidential Payroll Data"},
        }

    def find_by_id(self, doc_id: str):
        return self._db.get(doc_id)

doc_repo = DocumentRepository()
