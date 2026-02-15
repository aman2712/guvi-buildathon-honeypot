# Evaluator Scripts

These scripts let you regression-test the honeypot API as you adapt to the new evaluation spec.

## 1) Run multi-scenario API evaluation

```bash
npm run eval:run -- \
  --url http://localhost:5000/api/v1/message \
  --api-key dev-secret-key \
  --scenarios scripts/evaluator/scenarios.example.json \
  --timeout 30000 \
  --verbose true
```

Output:
- Writes a run report JSON under `reports/`
- Includes per-turn status checks:
  - HTTP 200
  - response under timeout
  - reply/message/text presence
- Includes full transcript for each scenario

## 2) Score final outputs with weighted scoring

Use when you have final outputs (for example from callback capture logs).

```bash
npm run eval:score -- \
  --scenarios scripts/evaluator/scenarios.example.json \
  --final-outputs scripts/evaluator/finalOutputs.example.json
```

Output:
- Writes score report JSON under `reports/`
- Computes:
  - scam detection (20)
  - intelligence extraction (40)
  - engagement quality (20)
  - response structure (20)
- Applies scenario weighted average

## Files

- `scripts/evaluator/scenarios.example.json`  
  Sample scenario definitions.
- `scripts/evaluator/finalOutputs.example.json`  
  Sample final output payloads for scoring script format.
- `scripts/evaluator/runEvaluation.js`  
  Runs turn-by-turn endpoint evaluation.
- `scripts/evaluator/scoreFinalOutputs.js`  
  Scores final outputs against scenarios.
