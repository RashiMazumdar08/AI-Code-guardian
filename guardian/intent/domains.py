"""
Business-domain taxonomy + evidence keyword sets.
Fully repository-agnostic: domains are inferred from evidence found in
README/docs, folder names, API routes, and code identifiers — never
assumed. Extend by adding a row; the classifier is data-driven.
"""
DOMAIN_KEYWORDS: dict[str, set[str]] = {
    "Banking / FinTech": {
        "loan", "account", "ledger", "payment", "transaction", "interest",
        "banking", "fintech", "kyc", "aml", "savings", "credit", "debit",
        "iban", "swift", "settlement", "remittance", "wallet",
    },
    "Healthcare": {
        "patient", "clinical", "diagnosis", "hipaa", "ehr", "emr",
        "prescription", "hospital", "medical", "pharmacy", "icd", "hl7", "fhir",
    },
    "Retail / E-commerce": {
        "cart", "checkout", "catalog", "inventory", "sku", "order",
        "shipping", "storefront", "product", "coupon", "pricing",
    },
    "Education": {
        "student", "course", "enrollment", "grade", "curriculum", "lms",
        "assignment", "lecture", "tuition",
    },
    "Insurance": {
        "policy", "claim", "premium", "underwriting", "actuarial",
        "coverage", "insured", "deductible",
    },
    "ERP / CRM": {
        "invoice", "procurement", "crm", "erp", "lead", "opportunity",
        "quotation", "vendor", "payroll", "hr",
    },
    "Government": {
        "citizen", "permit", "license", "municipal", "egovernance",
        "public sector", "compliance registry",
    },
    "Manufacturing / IoT": {
        "sensor", "telemetry", "mqtt", "firmware", "plc", "scada",
        "factory", "device", "iot", "edge",
    },
    "Cybersecurity": {
        "vulnerability", "cve", "owasp", "malware", "threat", "siem",
        "pentest", "scanner", "exploit", "forensics",
    },
    "Gaming": {
        "player", "leaderboard", "matchmaking", "gameplay", "quest",
        "multiplayer", "score",
    },
    "SaaS / Platform": {
        "tenant", "subscription", "billing", "workspace", "onboarding",
        "multi-tenant", "plan", "quota",
    },
}
