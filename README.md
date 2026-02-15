# Agentic Honeypot API

AI-powered honeypot API for scam detection, multi-turn engagement, and intelligence extraction for the GUVI hackathon flow.

## Tech Stack

- Node.js (ESM)
- Express
- OpenAI Responses API (JSON schema-constrained outputs)
- Axios
- In-memory session store (per `sessionId`)

## Project Structure

```text
your-repo/
├── README.md
├── src/
│   ├── main.js
│   ├── controllers/
│   ├── middleware/
│   ├── models/
│   ├── routes/
│   ├── services/
│   ├── storage/
│   └── utils/
├── scripts/
├── docs/
├── package.json
├── .env.example
└── Procfile
```

## API Endpoint

- **Method:** `POST`
- **Path:** `/api/v1/message`
- **Auth header:** `x-api-key: <API_KEY>`
- **Health check:** `GET /health`

## Request Shape

```json
{
  "sessionId": "uuid-string",
  "message": {
    "sender": "scammer",
    "text": "message text",
    "timestamp": "2026-01-21T10:15:30Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

## Response Shape

```json
{
  "status": "success",
  "reply": "honeypot response"
}
```

For non-scam turns, the API returns:

```json
{
  "status": "success",
  "reply": "",
  "message": "Message is not likely a scam."
}
```

## Final Callback

On conversation completion for scam sessions, the API sends a final result to:

- `POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult`

The payload includes:
- `sessionId`
- `scamDetected`
- `totalMessagesExchanged`
- `extractedIntelligence` (bankAccounts, upiIds, emailAddresses, phishingLinks, phoneNumbers, suspiciousKeywords)
- `engagementMetrics`
- `agentNotes`

## Local Setup

1. Install dependencies:

```bash
npm install
```

2. Create environment file:

```bash
cp .env.example .env
```

3. Set real values in `.env` (OpenAI key + API key).

4. Run server:

```bash
npm start
```

Server starts on `PORT` (default `5000`, or your configured value).

## Environment Variables

See `.env.example` for all keys. Required minimum:

- `OPENAI_API_KEY`
- `API_KEY`
- `PORT`

## Evaluation Scripts

Run full local evaluator:

```bash
npm run eval:run -- \
  --url http://localhost:9000/api/v1/message \
  --api-key your_api_key \
  --scenarios scripts/evaluator/scenarios.example.json \
  --timeout 30000
```

Run score script (example final outputs):

```bash
npm run eval:score -- \
  --scenarios scripts/evaluator/scenarios.example.json \
  --final-outputs scripts/evaluator/finalOutputs.example.json
```

Reports are written to `reports/`.

## Approach Summary

- Validates API key and request structure.
- Maintains per-session state keyed by `sessionId`.
- Detects scam likelihood (LLM + fallback heuristics).
- Engages scammer with controlled, human-like responses.
- Extracts intelligence continuously (LLM + regex fallbacks).
- Stops conversation on policy conditions and submits final callback once.
