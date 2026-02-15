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
  const expectedText = String(expected).toLowerCase();
  return normalizeArray(values).some((value) =>
    String(value).toLowerCase().includes(expectedText),
  );
}

function scoreScenario({ scenario, finalOutput }) {
  const score = {
    scamDetection: 0,
    intelligenceExtraction: 0,
    engagementQuality: 0,
    responseStructure: 0,
    total: 0,
    details: [],
  };

  // 1) Scam detection (20)
  if (finalOutput?.scamDetected === true) {
    score.scamDetection = 20;
  } else {
    score.details.push("scamDetected is false or missing");
  }

  // 2) Intelligence extraction (40 max)
  const fake = scenario.fakeData || {};
  const intel = finalOutput?.extractedIntelligence || {};
  const mappings = [
    { fakeKey: "phoneNumber", outKey: "phoneNumbers", points: 10 },
    { fakeKey: "bankAccount", outKey: "bankAccounts", points: 10 },
    { fakeKey: "upiId", outKey: "upiIds", points: 10 },
    { fakeKey: "phishingLink", outKey: "phishingLinks", points: 10 },
  ];
  for (const item of mappings) {
    if (!fake[item.fakeKey]) continue;
    if (containsValue(intel[item.outKey], fake[item.fakeKey])) {
      score.intelligenceExtraction += item.points;
    } else {
      score.details.push(
        `missing ${item.outKey} value ${fake[item.fakeKey]}`,
      );
    }
  }
  if (
    fake.emailAddress &&
    !containsValue(intel.emailAddresses || [], fake.emailAddress)
  ) {
    score.details.push("emailAddress present in scenario but not extracted");
  }
  score.intelligenceExtraction = Math.min(score.intelligenceExtraction, 40);

  // 3) Engagement quality (20)
  const metrics = finalOutput?.engagementMetrics || {};
  const duration = Number(metrics.engagementDurationSeconds || 0);
  const messages = Number(
    metrics.totalMessagesExchanged || finalOutput?.totalMessagesExchanged || 0,
  );

  if (duration > 0) score.engagementQuality += 5;
  if (duration > 60) score.engagementQuality += 5;
  if (messages > 0) score.engagementQuality += 5;
  if (messages >= 5) score.engagementQuality += 5;

  // 4) Response structure (20)
  const requiredFields = ["status", "scamDetected", "extractedIntelligence"];
  const optionalFields = ["engagementMetrics", "agentNotes"];
  for (const field of requiredFields) {
    if (Object.prototype.hasOwnProperty.call(finalOutput || {}, field)) {
      score.responseStructure += 5;
    } else {
      score.details.push(`missing required field: ${field}`);
    }
  }
  for (const field of optionalFields) {
    if (finalOutput && finalOutput[field]) score.responseStructure += 2.5;
  }
  score.responseStructure = Math.min(score.responseStructure, 20);

  score.total =
    score.scamDetection +
    score.intelligenceExtraction +
    score.engagementQuality +
    score.responseStructure;

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
  return weightedSum;
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

  if (!finalOutputsPath) {
    console.error("Missing --final-outputs path.");
    process.exit(1);
  }

  const scenarios = readJson(scenariosPath);
  const finalOutputs = readJson(finalOutputsPath);
  const perScenario = [];

  for (const scenario of scenarios) {
    const finalOutput = getFinalOutputForScenario(
      scenario.scenarioId,
      finalOutputs,
    );
    if (!finalOutput) {
      perScenario.push({
        scenarioId: scenario.scenarioId,
        weight: scenario.weight || 0,
        missingFinalOutput: true,
        score: {
          scamDetection: 0,
          intelligenceExtraction: 0,
          engagementQuality: 0,
          responseStructure: 0,
          total: 0,
          details: ["finalOutput missing for scenario"],
        },
      });
      continue;
    }

    const score = scoreScenario({ scenario, finalOutput });
    perScenario.push({
      scenarioId: scenario.scenarioId,
      weight: scenario.weight || 0,
      missingFinalOutput: false,
      score,
    });
  }

  const finalScore = weightedAverage(perScenario);
  const report = {
    generatedAt: new Date().toISOString(),
    finalScore,
    scenarios: perScenario,
  };

  const outDir = path.join(process.cwd(), "reports");
  ensureDir(outDir);
  const outFile =
    args.out || path.join(outDir, `evaluation-score-${Date.now()}.json`);
  fs.writeFileSync(outFile, JSON.stringify(report, null, 2));

  console.log(`Score report: ${outFile}`);
  console.log(`Weighted final score: ${finalScore.toFixed(2)}/100`);
}

main();
