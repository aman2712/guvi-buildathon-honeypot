import fs from "fs";
import path from "path";
import axios from "axios";
import { randomUUID } from "crypto";

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      args[key] = "true";
      continue;
    }
    args[key] = next;
    i += 1;
  }
  return args;
}

function readJsonFile(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}

function nowIso() {
  return new Date().toISOString();
}

function extractReplyFromResponse(data) {
  if (!data || typeof data !== "object") return "";
  if (typeof data.reply === "string") return data.reply;
  if (typeof data.message === "string") return data.message;
  if (typeof data.text === "string") return data.text;
  return "";
}

function detectTargetsFromHoneypotReply(reply = "") {
  const text = String(reply || "").toLowerCase();
  return {
    upi: /\bupi\b/.test(text),
    bank: /\bbank account\b|\baccount number\b|\baccount\b/.test(text),
    phone: /\bphone\b|\bnumber\b|\bcall\b|\bhelpline\b/.test(text),
    link: /\blink\b|\bwebsite\b|\burl\b|\bportal\b/.test(text),
    email: /\bemail\b|\bmail\b/.test(text),
    caseId: /\bcase\b|\breference\b/.test(text),
    name: /\bname\b|\bagent\b|\bwho should i ask for\b/.test(text),
  };
}

function nextUnsharedType(state, fakeData) {
  const priority = [
    "upiId",
    "bankAccount",
    "phoneNumber",
    "phishingLink",
    "emailAddress",
    "caseId",
    "agentName",
  ];
  for (const key of priority) {
    if (fakeData[key] && !state.shared[key]) return key;
  }
  return null;
}

function setShared(state, key) {
  if (!key) return;
  state.shared[key] = true;
}

function buildInfoSentence(type, value) {
  if (type === "upiId") return `Use UPI ID ${value} for verification`;
  if (type === "bankAccount") return `Use account number ${value} for this process`;
  if (type === "phoneNumber") return `You can reach our support at ${value}`;
  if (type === "phishingLink") return `Use this verification link ${value}`;
  if (type === "emailAddress") return `Send confirmation details to ${value}`;
  if (type === "caseId") return `Your case ID is ${value}`;
  if (type === "agentName") return `The assigned officer is ${value}`;
  return "";
}

function generateScammerFollowup({
  scenario,
  honeypotReply,
  turnNumber,
  state,
}) {
  const fakeData = scenario.fakeData || {};
  const asked = detectTargetsFromHoneypotReply(honeypotReply);
  const infoParts = [];

  if (asked.upi && fakeData.upiId) {
    infoParts.push(buildInfoSentence("upiId", fakeData.upiId));
    setShared(state, "upiId");
  }
  if (asked.bank && fakeData.bankAccount) {
    infoParts.push(buildInfoSentence("bankAccount", fakeData.bankAccount));
    setShared(state, "bankAccount");
  }
  if (asked.phone && fakeData.phoneNumber) {
    infoParts.push(buildInfoSentence("phoneNumber", fakeData.phoneNumber));
    setShared(state, "phoneNumber");
  }
  if (asked.link && fakeData.phishingLink) {
    infoParts.push(buildInfoSentence("phishingLink", fakeData.phishingLink));
    setShared(state, "phishingLink");
  }
  if (asked.email && fakeData.emailAddress) {
    infoParts.push(buildInfoSentence("emailAddress", fakeData.emailAddress));
    setShared(state, "emailAddress");
  }
  if (asked.caseId && fakeData.caseId) {
    infoParts.push(buildInfoSentence("caseId", fakeData.caseId));
    setShared(state, "caseId");
  }
  if (asked.name && fakeData.agentName) {
    infoParts.push(buildInfoSentence("agentName", fakeData.agentName));
    setShared(state, "agentName");
  }

  if (infoParts.length === 0) {
    const missingType = nextUnsharedType(state, fakeData);
    if (missingType) {
      infoParts.push(buildInfoSentence(missingType, fakeData[missingType]));
      setShared(state, missingType);
    }
  }

  const urgencyLines = [
    "Please share the OTP immediately to avoid account suspension.",
    "Act now or the account may be blocked in minutes.",
    "Do not delay, send OTP now for urgent verification.",
  ];
  const urgency = urgencyLines[(turnNumber - 1) % urgencyLines.length];

  const base = infoParts.length > 0
    ? `${infoParts.join(". ")}.`
    : "This is an urgent verification process.";

  return `${base} ${urgency}`.trim();
}

function computeRunChecks(turnResult, timeoutMs) {
  const checks = [];
  checks.push({
    name: "http_200",
    passed: turnResult.statusCode === 200,
    details: `status=${turnResult.statusCode}`,
  });
  checks.push({
    name: "response_under_30s",
    passed: turnResult.durationMs <= timeoutMs,
    details: `durationMs=${turnResult.durationMs}`,
  });
  checks.push({
    name: "has_reply_message_or_text",
    passed: Boolean(turnResult.reply),
    details: turnResult.reply ? "reply_present" : "reply_missing",
  });
  return checks;
}

async function runScenario({
  endpointUrl,
  apiKey,
  scenario,
  timeoutMs,
  verbose,
}) {
  const sessionId = randomUUID();
  const headers = { "Content-Type": "application/json" };
  if (apiKey) headers["x-api-key"] = apiKey;

  const conversationHistory = [];
  const transcript = [];
  const turnResults = [];
  const state = { shared: {} };

  for (let turn = 1; turn <= (scenario.maxTurns || 10); turn += 1) {
    const scammerText =
      turn === 1
        ? scenario.initialMessage
        : generateScammerFollowup({
            scenario,
            honeypotReply: transcript[transcript.length - 1]?.text || "",
            turnNumber: turn,
            state,
          });

    const scammerMessage = {
      sender: "scammer",
      text: scammerText,
      timestamp: nowIso(),
    };

    const payload = {
      sessionId,
      message: scammerMessage,
      conversationHistory,
      metadata: scenario.metadata || {},
    };

    const startedAt = Date.now();
    let statusCode = 0;
    let data = null;
    let reply = "";
    let error = null;

    try {
      const response = await axios.post(endpointUrl, payload, {
        headers,
        timeout: timeoutMs,
        validateStatus: () => true,
      });
      statusCode = response.status;
      data = response.data;
      reply = extractReplyFromResponse(data);
    } catch (err) {
      error = err.message || "request_failed";
    }
    const durationMs = Date.now() - startedAt;

    const turnResult = {
      turn,
      statusCode,
      durationMs,
      reply,
      responseBody: data,
      error,
      checks: [],
    };
    turnResult.checks = computeRunChecks(turnResult, timeoutMs);
    turnResults.push(turnResult);

    transcript.push({
      sender: "scammer",
      text: scammerText,
      timestamp: scammerMessage.timestamp,
    });

    if (reply) {
      const honeypotMessage = {
        sender: "user",
        text: reply,
        timestamp: nowIso(),
      };
      transcript.push(honeypotMessage);
      conversationHistory.push(scammerMessage, honeypotMessage);
    } else {
      conversationHistory.push(scammerMessage);
    }

    if (verbose) {
      console.log(`[${scenario.scenarioId}] Turn ${turn} status=${statusCode} durationMs=${durationMs}`);
      if (error) console.log(`[${scenario.scenarioId}] Error: ${error}`);
      if (reply) console.log(`[${scenario.scenarioId}] Honeypot: ${reply}`);
    }

    if (error || statusCode !== 200) break;
  }

  const avgResponseMs =
    turnResults.length === 0
      ? 0
      : turnResults.reduce((sum, t) => sum + t.durationMs, 0) / turnResults.length;
  const allChecks = turnResults.flatMap((t) => t.checks);
  const passedChecks = allChecks.filter((c) => c.passed).length;
  const failedChecks = allChecks.length - passedChecks;

  return {
    scenarioId: scenario.scenarioId,
    scenarioName: scenario.name,
    scamType: scenario.scamType,
    weight: scenario.weight,
    sessionId,
    turnCount: turnResults.length,
    avgResponseMs,
    passedChecks,
    failedChecks,
    turnResults,
    transcript,
    fakeData: scenario.fakeData || {},
  };
}

function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
}

async function main() {
  const args = parseArgs(process.argv);
  const endpointUrl = args.url || process.env.EVAL_ENDPOINT_URL;
  const apiKey = args["api-key"] || process.env.EVAL_API_KEY || "";
  const scenariosPath =
    args.scenarios ||
    path.join(process.cwd(), "scripts", "evaluator", "scenarios.example.json");
  const timeoutMs = Number(args.timeout || 30000);
  const verbose = args.verbose === "true";

  if (!endpointUrl) {
    console.error("Missing endpoint URL. Use --url or EVAL_ENDPOINT_URL.");
    process.exit(1);
  }

  const scenarios = readJsonFile(scenariosPath);
  if (!Array.isArray(scenarios) || scenarios.length === 0) {
    console.error("Scenarios file must be a non-empty JSON array.");
    process.exit(1);
  }

  const runStartedAt = new Date().toISOString();
  const scenarioResults = [];

  for (const scenario of scenarios) {
    console.log(`Running scenario: ${scenario.scenarioId}`);
    const result = await runScenario({
      endpointUrl,
      apiKey,
      scenario,
      timeoutMs,
      verbose,
    });
    scenarioResults.push(result);
  }

  const summary = {
    endpointUrl,
    runStartedAt,
    runFinishedAt: new Date().toISOString(),
    scenarioCount: scenarioResults.length,
    avgResponseMs:
      scenarioResults.reduce((sum, s) => sum + s.avgResponseMs, 0) /
      scenarioResults.length,
    totalFailedChecks: scenarioResults.reduce(
      (sum, s) => sum + s.failedChecks,
      0,
    ),
  };

  const report = { summary, scenarios: scenarioResults };

  const outDir = path.join(process.cwd(), "reports");
  ensureDir(outDir);
  const outFile =
    args.out ||
    path.join(outDir, `evaluation-run-${Date.now()}.json`);
  fs.writeFileSync(outFile, JSON.stringify(report, null, 2));

  console.log(`\nEvaluation run complete.`);
  console.log(`Report: ${outFile}`);
  console.log(
    `Average response time: ${summary.avgResponseMs.toFixed(2)} ms | failed checks: ${summary.totalFailedChecks}`,
  );
}

main().catch((error) => {
  console.error("Evaluation run failed:", error);
  process.exit(1);
});
