# AI Code Guardian — AI Security Copilot

The copilot uses NVIDIA Nemotron for chat inference and local embeddings
for retrieval. Source snippets selected for chat are redacted by
`guardian.llm.guardrails` before they are sent to the NVIDIA endpoint.
Embeddings never leave the machine.

## Architecture

```
User Question
    |
    v
EmbeddingRouter ---- CodeBERT (code) -------- FAISS Code Index
    |           `--- LocalEmbedder (text) ---- FAISS Doc Index
    |
    v
Retriever
  |-- Intent classification
  |-- Hybrid FAISS search
  |-- Deduplication
  `-- Context assembly
    |
    v
PromptBuilder
  |-- System prompt and guardrails
  |-- Repository summary
  |-- Retrieved context
  |-- Citations
  |-- Conversation history
  `-- User question
    |
    v
NemotronLLM.chat_stream()
    |
    v
Streamlit streaming render + citations panel
```

## Module Map

| File | Responsibility |
|---|---|
| `config.py` | Assistant tunables and local embedding defaults |
| `models.py` | Data types: Document, RetrievedChunk, RAGResult, AssistantResponse |
| `local_embedder.py` | Local sentence-transformers embeddings |
| `codebert.py` | CodeBERT semantic embeddings for source code |
| `document_loader.py` | Reads every file type into chunked Document objects |
| `embeddings.py` | Routes code to CodeBERT and text to LocalEmbedder |
| `vector_store.py` | FAISS index management: build, persist, load, query |
| `code_indexer.py` | Orchestrates load, embed, and store pipeline |
| `retriever.py` | Intent classification, hybrid search, context merge |
| `prompt_builder.py` | Structured prompt assembly with grounding guardrail |
| `conversation_memory.py` | Per-session chat history and context state |
| `rag_pipeline.py` | End-to-end RAG, non-streaming and streaming |
| `chatbot.py` | `AISecurityCopilot` facade and factory |
| `dashboard/chat_page.py` | Streamlit UI: file upload, streaming chat, index panel |

## Setup

```bash
export NVIDIA_API_KEY='nvapi-...'
export NVIDIA_BASE_URL='https://integrate.api.nvidia.com/v1'
export NVIDIA_MODEL='nvidia/llama-3.3-nemotron-super-49b-v1'

pip install -r requirements_ai.txt
streamlit run dashboard/app.py
```

Optional CodeBERT dependencies:

```bash
pip install torch transformers
```

## Configuration

| Env var | Default | Description |
|---|---|---|
| `NVIDIA_API_KEY` | unset | Required key for Nemotron inference |
| `NVIDIA_BASE_URL` | `https://integrate.api.nvidia.com/v1` | NVIDIA OpenAI-compatible endpoint |
| `NVIDIA_MODEL` | `nvidia/llama-3.3-nemotron-super-49b-v1` | Chat model |
| `ACG_EMBED_MODEL` | `sentence-transformers/all-MiniLM-L6-v2` | Local embedding model |
| `ACG_EMBED_DIM` | `384` | Embedding dimension |
| `ACG_CODEBERT_DEVICE` | `cpu` | `cpu` or `cuda` |
| `ACG_LOG_LEVEL` | `INFO` | Logging verbosity |

## Usage

```python
from pathlib import Path
from guardian.ai.chatbot import AISecurityCopilot

copilot = AISecurityCopilot.create()
copilot.index_directory(Path("./my_project"))

response = copilot.ask("Show all SQL injection risks")
print(response.answer)
print("Sources:", response.citations)

for token in copilot.ask_stream("Explain the authentication flow"):
    print(token, end="", flush=True)
```

## Grounding Guarantee

The system prompt requires the assistant to say it could not find
evidence when retrieved repository context does not support an answer.
The LLM must not invent file names, line numbers, or vulnerability
details.
