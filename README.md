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
