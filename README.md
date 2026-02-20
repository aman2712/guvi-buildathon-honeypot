# Honeypot API

## Description
This project is an agentic honeypot API for scam detection. It receives suspected scam messages, classifies scam intent, engages the scammer in multi-turn chat without revealing detection, extracts scam intelligence, and sends final results to the GUVI callback endpoint.

## Tech Stack
- Language/Framework: Node.js (ESM), Express
- Key libraries: `axios`, `dotenv`
- LLM/AI models used: OpenAI Responses API (`gpt-4o-mini` by default)

## Setup Instructions
1. Clone the repository
2. Install dependencies
3. Set environment variables
4. Run the application

```bash
git clone <your-repo-url>
cd guvi-hackathon-honeypot
npm install
cp .env.example .env
npm start
```

## API Endpoint
- URL: `https://corelogic-honeypot-api-6861640fafb9.herokuapp.com/api/v1/message`
- Method: `POST`
- Authentication: `x-api-key` header

### Request Example
```bash
curl -X POST "https://corelogic-honeypot-api-6861640fafb9.herokuapp.com/api/v1/message" \
  -H "Content-Type: application/json" \
  -H "x-api-key: <YOUR_API_KEY>" \
  -d '{
    "sessionId": "test-session-001",
    "message": {
      "sender": "scammer",
      "text": "URGENT: Your account is blocked. Share OTP now.",
      "timestamp": "2026-02-20T10:00:00Z"
    },
    "conversationHistory": [],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```

### Response Example
```json
{
  "status": "success",
  "reply": "I saw your OTP request. Which official number should I call if this fails?"
}
```

### Error Behavior
- Invalid `x-api-key` -> `401` with `{"status":"failed","reply":"","message":"Unauthorized"}`
- Invalid JSON body -> `400` with `{"status":"failed","reply":"","message":"Invalid JSON body"}`
- Unexpected runtime failure on valid message envelope -> safe `200` fallback reply (conversation continues)

## Approach
- How you detect scams:
  - Classifier prompt with structured JSON output (`scamLikely`, `scamType`, confidence, reasons)
  - Rule-based fallback when LLM is unavailable
- How you extract intelligence:
  - Incremental extraction from conversation with structured LLM output
  - Regex/heuristic fallback extraction for resilience
  - Tracks bank accounts, UPI IDs, email addresses, links, phone numbers, case IDs, names, and scam signals
- How you maintain engagement:
  - Session-based conversation memory by `sessionId`
  - Controlled persona replies with target-driven prompts to collect missing intel
  - Stop logic + disengagement message + one-time final GUVI callback

## Local Evaluation
```bash
# 1) Start API
npm start

# 2) Run evaluator against local API
node scripts/evaluator/runEvaluation.js \
  --url http://localhost:5000/api/v1/message \
  --api-key "$API_KEY" \
  --scenarios scripts/evaluator/scenarios.fullsuite.json

# 3) Build final outputs from callback capture
node scripts/evaluator/buildFinalOutputsFromCallbacks.js \
  --run-report reports/evaluation-run-fullsuite.json \
  --callbacks reports/callback-capture.fullsuite.jsonl \
  --out scripts/evaluator/finalOutputs.fullsuite.generated.json

# 4) Score with updated rubric
node scripts/evaluator/scoreFinalOutputs.js \
  --scenarios scripts/evaluator/scenarios.fullsuite.json \
  --final-outputs scripts/evaluator/finalOutputs.fullsuite.generated.json \
  --run-report reports/evaluation-run-fullsuite.json \
  --code-quality 10 \
  --out reports/evaluation-score-fullsuite.json
```
