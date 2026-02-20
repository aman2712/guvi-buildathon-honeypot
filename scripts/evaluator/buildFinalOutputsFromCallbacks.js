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

function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function readJsonLines(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

function main() {
  const args = parseArgs(process.argv);
  const runReportPath = args["run-report"];
  const callbacksPath = args.callbacks;
  const outPath =
    args.out ||
    path.join(process.cwd(), "scripts", "evaluator", "finalOutputs.fromCallbacks.json");

  if (!runReportPath || !callbacksPath) {
    console.error("Usage: --run-report <file> --callbacks <jsonl-file> [--out <file>]");
    process.exit(1);
  }

  const runReport = readJson(runReportPath);
  const callbacks = readJsonLines(callbacksPath);
  const callbackBySession = new Map();
  for (const payload of callbacks) {
    if (!payload?.sessionId) continue;
    callbackBySession.set(payload.sessionId, payload);
  }

  const finalOutputs = {};
  for (const scenario of runReport.scenarios || []) {
    const payload = callbackBySession.get(scenario.sessionId);
    if (!payload) continue;
    finalOutputs[scenario.scenarioId] = payload;
  }

  ensureDir(path.dirname(outPath));
  fs.writeFileSync(outPath, JSON.stringify(finalOutputs, null, 2));
  console.log(`Generated final outputs: ${outPath}`);
}

main();
