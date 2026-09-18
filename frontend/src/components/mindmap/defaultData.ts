import { MindMapData } from "./types";

export const defaultMindMapData: MindMapData = {
  nodes: [
    {
      id: "root",
      type: "folder",
      data: {
        label: "AI-Code-Guardian",
        path: "/",
        riskScore: 65,
      },
    },
    {
      id: "folder-services",
      type: "folder",
      data: {
        label: "services",
        path: "/services",
        riskScore: 85,
      },
    },
    {
      id: "file-payment",
      type: "file",
      data: {
        label: "payment_service.py",
        path: "services/payment_service.py",
        language: "python",
        riskScore: 92,
        codePreview: `def process_user_payment(user_id, amount):\n    cursor = db.cursor()\n    # Vulnerable SQL concatenation\n    query = "SELECT * FROM accounts WHERE id = " + user_id\n    cursor.execute(query)\n    return cursor.fetchall()`,
        findings: [
          {
            category: "SQL Injection",
            severity: "Critical",
            reason: "Untrusted string user_id flows directly into database execution sink.",
            cwe: "CWE-89",
          },
        ],
      },
    },
    {
      id: "func-process-payment",
      type: "function",
      data: {
        label: "process_user_payment",
        codePreview: `def process_user_payment(user_id, amount):\n    cursor.execute("SELECT * FROM accounts WHERE id = " + user_id)`,
      },
    },
    {
      id: "finding-sqli",
      type: "finding",
      data: {
        label: "SQL Injection (CWE-89)",
        path: "services/payment_service.py:42",
        severity: "critical",
        reason: "User input concatenated into query string.",
      },
    },
    {
      id: "folder-utils",
      type: "folder",
      data: {
        label: "utils",
        path: "/utils",
        riskScore: 40,
      },
    },
    {
      id: "file-crypto",
      type: "file",
      data: {
        label: "crypto.py",
        path: "utils/crypto.py",
        language: "python",
        riskScore: 70,
        codePreview: `import hashlib\n\ndef hash_secret(secret_key):\n    return hashlib.md5(secret_key.encode()).hexdigest()`,
        findings: [
          {
            category: "Weak Crypto",
            severity: "High",
            reason: "MD5 is collision-broken and deprecated by NIST.",
            cwe: "CWE-327",
          },
        ],
      },
    },
    {
      id: "func-hash-secret",
      type: "function",
      data: {
        label: "hash_secret",
        codePreview: `def hash_secret(secret_key):\n    return hashlib.md5(secret_key.encode()).hexdigest()`,
      },
    },
    {
      id: "finding-md5",
      type: "finding",
      data: {
        label: "Weak Crypto (MD5)",
        path: "utils/crypto.py:18",
        severity: "high",
        reason: "MD5 hashing algorithm detected.",
      },
    },
    {
      id: "class-auth-manager",
      type: "class",
      data: {
        label: "AuthManager",
        path: "services/auth.py",
      },
    },
    {
      id: "module-ast-parser",
      type: "module",
      data: {
        label: "tree_sitter_parser",
        path: "guardian/ust/parsers.py",
      },
    },
  ],
  edges: [
    { id: "e-root-services", source: "root", target: "folder-services", type: "default" },
    { id: "e-services-payment", source: "folder-services", target: "file-payment", type: "default" },
    { id: "e-payment-func", source: "file-payment", target: "func-process-payment", type: "call" },
    { id: "e-func-finding", source: "func-process-payment", target: "finding-sqli", type: "dependency" },
    { id: "e-root-utils", source: "root", target: "folder-utils", type: "default" },
    { id: "e-utils-crypto", source: "folder-utils", target: "file-crypto", type: "default" },
    { id: "e-crypto-func", source: "file-crypto", target: "func-hash-secret", type: "call" },
    { id: "e-crypto-finding", source: "func-hash-secret", target: "finding-md5", type: "dependency" },
    { id: "e-services-auth", source: "folder-services", target: "class-auth-manager", type: "default" },
    { id: "e-root-module", source: "root", target: "module-ast-parser", type: "import" },
  ],
};
