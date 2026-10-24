# Agent integration (LangChain + OpenAI)

Environment variables
4:- `OPENAI_API_KEY` — required to use OpenAI via LangChain and RAG.
- `USE_LOCAL_LLAMA` — (optional) set to `1` to prefer a local Llama executable; not configured by default.
- `LLAMA_MODEL_PATH` — (optional) local model path if using a local Llama integration.

Endpoints
- `POST /api/agent/langchain` — requires authentication header `Authorization: Bearer <token>`.
  - Body: `{ "message": "Your prompt here" }`
  - Response: `{ source: "openai-langchain"|"local-llama", answer: "..." }`
- `POST /api/agent/rag` — requires authentication header `Authorization: Bearer <token>`.
  - Body: `{ "message": "Your prompt here" }`
  - Response: `{ source: "openai-rag", answer: "..." }`

Quick start
1. Install server deps:
```bash
cd server
npm install
```
2. Set `OPENAI_API_KEY` in your environment.
3. Start the server:
```bash
npm run dev
```
4. Example curl request (replace token):
```bash
curl -X POST http://localhost:5000/api/agent/langchain \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"message":"How can I remediate public blob access on Azure storage accounts?"}'
```

Notes
- The project includes a helper at `server/agents/langchainAgent.js` that prefers a local Llama when `USE_LOCAL_LLAMA` is set, falling back to OpenAI/ LangChain. Because local native Llama integrations often require native binaries and platform setup, follow the `llama-cpp` or `gpt4all` project docs to prepare a local model if desired.
