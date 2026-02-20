import fs from "fs";
import path from "path";

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

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function normalizeArray(value) {
  if (Array.isArray(value)) return value.map((v) => String(v));
  if (value == null) return [];
  return [String(value)];
}

function containsValue(values, expected) {
  const expectedText = String(expected || "").toLowerCase();
  if (!expectedText) return false;
  return normalizeArray(values).some((value) =>
    String(value).toLowerCase().includes(expectedText),
  );
}

function countMatches(messages = [], regexes = []) {
  return messages.filter((msg) => regexes.some((re) => re.test(msg.text || ""))).length;
}

function getScenarioContext(scenarioId, runReport) {
  if (!runReport?.scenarios) return null;
  return runReport.scenarios.find((s) => s.scenarioId === scenarioId) || null;
}

function scoreConversationQuality(transcript = [], details = []) {
  if (!Array.isArray(transcript) || transcript.length === 0) {
    details.push("conversation transcript missing; conversationQuality=0");
    return 0;
  }

  const userMessages = transcript.filter((m) => m.sender === "user");
  const scammerMessages = transcript.filter((m) => m.sender === "scammer");

  let score = 0;

  // Turn count score (max 8)
  const turnCount = scammerMessages.length;
  if (turnCount >= 8) score += 8;
  else if (turnCount >= 6) score += 6;
  else if (turnCount >= 4) score += 3;

  // Questions asked score (max 4)
  const questionsAsked = userMessages.filter((m) => /\?/.test(m.text || "")).length;
  if (questionsAsked >= 5) score += 4;
  else if (questionsAsked >= 3) score += 2;
  else if (questionsAsked >= 1) score += 1;

  // Relevant questions score (max 3)
  const relevantPatterns = [
    /\b(case|reference|id)\b/i,
    /\b(organization|company|department|team)\b/i,
    /\b(phone|number|helpline|call|contact)\b/i,
    /\b(website|link|url|portal)\b/i,
    /\b(email|mail)\b/i,
    /\b(upi|bank account|account number)\b/i,
    /\b(policy|order|tracking)\b/i,
  ];
  const relevantQuestions = userMessages.filter(
    (m) => /\?/.test(m.text || "") && relevantPatterns.some((re) => re.test(m.text || "")),
  ).length;
  if (relevantQuestions >= 3) score += 3;
  else if (relevantQuestions >= 2) score += 2;
  else if (relevantQuestions >= 1) score += 1;

  // Red flag identification score (max 8)
  const redFlagPatterns = [
    /\burgent|immediately|act now|deadline|minutes?\b/i,
    /\botp|pin|password|credentials?\b/i,
    /\bblocked|suspended|freeze|locked|compromised\b/i,
    /\bfee|payment|transfer|verification amount\b/i,
    /\blink|website|url|phishing\b/i,
  ];
  const redFlagMentions = countMatches(userMessages, redFlagPatterns);
  if (redFlagMentions >= 5) score += 8;
  else if (redFlagMentions >= 3) score += 5;
  else if (redFlagMentions >= 1) score += 2;

  // Information elicitation score (max 7)
  const elicitationPatterns = [
    /\b(what|which|who|where|can you|could you)\b/i,
    /\b(upi|account|phone|number|helpline|link|website|email|case|id|policy|order|tracking|organization|department)\b/i,
  ];
  const elicitationAttempts = userMessages.filter(
    (m) => /\?/.test(m.text || "") && elicitationPatterns.every((re) => re.test(m.text || "")),
  ).length;
  score += Math.min(7, elicitationAttempts * 1.5);

  return Math.min(30, Number(score.toFixed(2)));
}

function getEngagementMetrics(finalOutput = {}) {
  const duration = Number(
    finalOutput.engagementDurationSeconds ??
      finalOutput.engagementMetrics?.engagementDurationSeconds ??
      0,
  );
  const messages = Number(
    finalOutput.totalMessagesExchanged ??
      finalOutput.engagementMetrics?.totalMessagesExchanged ??
      0,
  );
  return { duration, messages };
}

function scoreEngagementQuality(finalOutput = {}) {
  const { duration, messages } = getEngagementMetrics(finalOutput);
  let score = 0;

  if (duration > 0) score += 1;
  if (duration > 60) score += 2;
  if (duration > 180) score += 1;
  if (messages > 0) score += 2;
  if (messages >= 5) score += 3;
  if (messages >= 10) score += 1;

  return Math.min(10, score);
}

function scoreResponseStructure(finalOutput = {}, details = []) {
  let score = 0;
  let penalty = 0;

  if (Object.prototype.hasOwnProperty.call(finalOutput, "sessionId")) score += 2;
  else {
    details.push("missing required field: sessionId");
    penalty += 1;
  }

  if (Object.prototype.hasOwnProperty.call(finalOutput, "scamDetected")) score += 2;
  else {
    details.push("missing required field: scamDetected");
    penalty += 1;
  }

  if (Object.prototype.hasOwnProperty.call(finalOutput, "extractedIntelligence")) score += 2;
  else {
    details.push("missing required field: extractedIntelligence");
    penalty += 1;
  }

  if (
    Object.prototype.hasOwnProperty.call(finalOutput, "totalMessagesExchanged") &&
    (Object.prototype.hasOwnProperty.call(finalOutput, "engagementDurationSeconds") ||
      Object.prototype.hasOwnProperty.call(finalOutput, "engagementMetrics"))
  ) {
    score += 1;
  }

  if (finalOutput.agentNotes) score += 1;
  if (finalOutput.scamType) score += 1;
  if (
    Object.prototype.hasOwnProperty.call(finalOutput, "confidenceLevel") &&
    Number.isFinite(Number(finalOutput.confidenceLevel))
  ) {
    score += 1;
  }

  score = score - penalty;
  if (score < 0) score = 0;
  return Math.min(10, score);
}

function getExtractedValues(finalOutput = {}, fakeKey = "") {
  const intel = finalOutput.extractedIntelligence || {};
  const mappings = {
    phoneNumber: intel.phoneNumbers,
    bankAccount: intel.bankAccounts,
    upiId: intel.upiIds,
    phishingLink: intel.phishingLinks,
    emailAddress: intel.emailAddresses,
    caseId: intel.caseIds,
    policyNumber: intel.policyNumbers,
    orderNumber: intel.orderNumbers,
    staffId: intel.staffIds,
    agentName: intel.agentNames,
  };
  if (Object.prototype.hasOwnProperty.call(mappings, fakeKey)) {
    return mappings[fakeKey];
  }
  // Generic fallback for unknown keys.
  return intel[`${fakeKey}s`] || intel[fakeKey] || [];
}

function isFakeFieldExtracted(fakeKey, fakeValue, finalOutput = {}) {
  const extractedValues = getExtractedValues(finalOutput, fakeKey);
  if (containsValue(extractedValues, fakeValue)) return true;
  // Fallback: many implementations include extra IDs in agentNotes.
  return containsValue([finalOutput.agentNotes || ""], fakeValue);
}

function scoreIntelligenceExtraction(scenario = {}, finalOutput = {}, details = []) {
  const fake = scenario.fakeData || {};
  const fakeItems = Object.entries(fake).filter(
    ([, value]) => value !== null && value !== undefined && String(value).trim() !== "",
  );
  if (fakeItems.length === 0) return 0;

  const perItem = 30 / fakeItems.length;
  let score = 0;

  for (const [fakeKey, fakeValue] of fakeItems) {
    if (isFakeFieldExtracted(fakeKey, fakeValue, finalOutput)) {
      score += perItem;
    } else {
      details.push(`missing fakeData field extraction: ${fakeKey}=${fakeValue}`);
    }
  }

  return Number(Math.min(30, score).toFixed(2));
}

function scoreScenario({ scenario, finalOutput, transcript }) {
  const score = {
    scamDetection: 0,
    intelligenceExtraction: 0,
    conversationQuality: 0,
    engagementQuality: 0,
    responseStructure: 0,
    total: 0,
    details: [],
  };

  if (finalOutput?.scamDetected === true) {
    score.scamDetection = 20;
  } else {
    score.details.push("scamDetected is false or missing");
  }

  score.intelligenceExtraction = scoreIntelligenceExtraction(
    scenario,
    finalOutput,
    score.details,
  );
  score.conversationQuality = scoreConversationQuality(transcript, score.details);
  score.engagementQuality = scoreEngagementQuality(finalOutput);
  score.responseStructure = scoreResponseStructure(finalOutput, score.details);

  score.total = Number(
    (
      score.scamDetection +
      score.intelligenceExtraction +
      score.conversationQuality +
      score.engagementQuality +
      score.responseStructure
    ).toFixed(2),
  );

  return score;
}

function getFinalOutputForScenario(scenarioId, finalOutputs) {
  if (!finalOutputs || typeof finalOutputs !== "object") return null;
  if (finalOutputs[scenarioId]) return finalOutputs[scenarioId];
  if (Array.isArray(finalOutputs)) {
    return finalOutputs.find((f) => f.scenarioId === scenarioId) || null;
  }
  return null;
}

function weightedAverage(items) {
  const totalWeight = items.reduce((sum, i) => sum + Number(i.weight || 0), 0);
  if (totalWeight === 0) return 0;
  const weightedSum = items.reduce(
    (sum, i) => sum + i.score.total * (Number(i.weight || 0) / totalWeight),
    0,
  );
  return Number(weightedSum.toFixed(2));
}

function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
}

function main() {
  const args = parseArgs(process.argv);
  const scenariosPath =
    args.scenarios ||
    path.join(process.cwd(), "scripts", "evaluator", "scenarios.example.json");
  const finalOutputsPath = args["final-outputs"];
  const runReportPath = args["run-report"] || "";
  const codeQuality = Number(args["code-quality"] || 10);

  if (!finalOutputsPath) {
    console.error("Missing --final-outputs path.");
    process.exit(1);
  }

  const scenarios = readJson(scenariosPath);
  const finalOutputs = readJson(finalOutputsPath);
  const runReport = runReportPath ? readJson(runReportPath) : null;
  const perScenario = [];

  for (const scenario of scenarios) {
    const finalOutput = getFinalOutputForScenario(
      scenario.scenarioId,
      finalOutputs,
    );
    const scenarioContext = getScenarioContext(scenario.scenarioId, runReport);
    const transcript = scenarioContext?.transcript || [];

    if (!finalOutput) {
      perScenario.push({
        scenarioId: scenario.scenarioId,
        weight: scenario.weight || 0,
        missingFinalOutput: true,
        score: {
          scamDetection: 0,
          intelligenceExtraction: 0,
          conversationQuality: 0,
          engagementQuality: 0,
          responseStructure: 0,
          total: 0,
          details: ["finalOutput missing for scenario"],
        },
      });
      continue;
    }

    const score = scoreScenario({ scenario, finalOutput, transcript });
    perScenario.push({
      scenarioId: scenario.scenarioId,
      weight: scenario.weight || 0,
      missingFinalOutput: false,
      score,
    });
  }

  const scenarioWeightedScore = weightedAverage(perScenario);
  const finalScore = Number((scenarioWeightedScore * 0.9 + codeQuality).toFixed(2));

  const report = {
    generatedAt: new Date().toISOString(),
    scenarioWeightedScore,
    codeQuality,
    finalScore,
    scenarios: perScenario,
  };

  const outDir = path.join(process.cwd(), "reports");
  ensureDir(outDir);
  const outFile =
    args.out || path.join(outDir, `evaluation-score-${Date.now()}.json`);
  fs.writeFileSync(outFile, JSON.stringify(report, null, 2));

  console.log(`Score report: ${outFile}`);
  console.log(`Weighted scenario score: ${scenarioWeightedScore.toFixed(2)}/100`);
  console.log(`Final score (with code quality): ${finalScore.toFixed(2)}/100`);
}

main();
