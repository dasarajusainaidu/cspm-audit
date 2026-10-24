# CSPM Auditor

Animated MERN dashboard for monitoring Azure security posture. It supports JWT login/register, role-based dashboards, live scan progress through Socket.IO, searchable findings, remediation tracking, and an AI security assistant.

## Run

1. Copy `.env.example` to `server/.env` and set the values.
2. Install packages with `npm install`.
3. Start with `npm run dev`.
4. Open `http://localhost:5173`.

If MongoDB is unavailable, the API uses an in-memory demo store so the full UI can still be shown. Add `MONGODB_URI` for persistence. The AI assistant uses OpenAI when `OPENAI_API_KEY` is present, otherwise it returns safety-focused local guidance.
