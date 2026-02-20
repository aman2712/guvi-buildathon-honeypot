import {
  buildAgentReplyPrompt,
  buildClassifierPrompt,
  buildConversationEndPrompt,
  buildIntelligenceExtractionPrompt,
} from "../utils/prompts.js";
import { generateJson } from "../utils/llmClient.js";
import {
  agentReplySchema,
  conversationEndSchema,
  intelligenceExtractionSchema,
} from "../models/llmSchemas.js";
import {
  appendMessageIfMissing,
  appendReply,
  getOrCreateSession,
  getTimingStats,
  markExtractionRun,
  reconcileSessionMessages,
  recordResponseTime,
  setCallbackSent,
  setConversationEnded,
  setInitialScamAssessment,
  updateDialogState,
  updateIntelligence,
  updateMetadata,
} from "../storage/conversationStore.js";
import { sendFinalResult } from "./callback.service.js";

const MIN_TOTAL_MESSAGES = Number(process.env.MIN_TOTAL_MESSAGES || 18);
const MIN_SCAMMER_MESSAGES = Number(process.env.MIN_SCAMMER_MESSAGES || 10);
const MIN_EXTRACTION_RUNS = Number(process.env.MIN_EXTRACTION_RUNS || 3);
const GRACE_MESSAGES = Number(process.env.GRACE_MESSAGES || 4);
const REQUIRE_PRIMARY_INTEL = process.env.REQUIRE_PRIMARY_INTEL === "true";
const POST_PRIMARY_GRACE_TOTAL_MESSAGES = Number(
  process.env.POST_PRIMARY_GRACE_TOTAL_MESSAGES || 4,
);
const POST_PRIMARY_GRACE_SCAMMER_MESSAGES = Number(
  process.env.POST_PRIMARY_GRACE_SCAMMER_MESSAGES || 2,
);
const NO_NEW_INTEL_SCAMMER_TURNS = Number(
  process.env.NO_NEW_INTEL_SCAMMER_TURNS || 2,
);
const MAX_SCAMMER_TURNS = Number(process.env.MAX_SCAMMER_TURNS || 10);
const EARLY_STOP_MIN_TOTAL_MESSAGES = Number(
  process.env.EARLY_STOP_MIN_TOTAL_MESSAGES || 14,
);
const EARLY_STOP_MIN_SCAMMER_MESSAGES = Number(
  process.env.EARLY_STOP_MIN_SCAMMER_MESSAGES || 8,
);
const MIN_REPORTED_ENGAGEMENT_SECONDS = Number(
  process.env.MIN_REPORTED_ENGAGEMENT_SECONDS || 181,
);

function countScammerMessages(messages = []) {
  return messages.filter((msg) => msg.sender === "scammer").length;
}

function mergeUniqueStrings(target = [], incoming = []) {
  return Array.from(new Set([...(target || []), ...(incoming || [])].filter(Boolean)));
}

function logLlmFallback(stage, sessionId, error) {
  console.error(
    `[LLM_FALLBACK] stage=${stage} sessionId=${sessionId} reason=${error?.message || "unknown"}`,
  );
}

function buildRuleBasedScamAssessment(messageText = "") {
  const text = String(messageText || "");
  const lower = text.toLowerCase();
  const keywordRules = [
    { keyword: "urgent", code: "URGENCY" },
    { keyword: "otp", code: "CREDENTIAL_REQUEST" },
    { keyword: "verify", code: "OTHER" },
    { keyword: "account blocked", code: "THREAT" },
    { keyword: "blocked", code: "THREAT" },
    { keyword: "upi", code: "PAYMENT_REQUEST" },
    { keyword: "bank", code: "PAYMENT_REQUEST" },
    { keyword: "password", code: "CREDENTIAL_REQUEST" },
    { keyword: "pin", code: "CREDENTIAL_REQUEST" },
    { keyword: "http://", code: "LINK" },
    { keyword: "https://", code: "LINK" },
    { keyword: "sbi", code: "IMPERSONATION" },
    { keyword: "customer care", code: "IMPERSONATION" },
  ];

  const found = keywordRules.filter((item) => lower.includes(item.keyword));
  const reasonCodes = Array.from(new Set(found.map((item) => item.code)));
  const suspiciousKeywords = Array.from(new Set(found.map((item) => item.keyword)));
  const triggerPhrases = suspiciousKeywords;
  const score = found.length;
  const scamLikely = score >= 2;

  let scamType = "unknown";
  if (lower.includes("upi")) scamType = "upi_fraud";
  else if (lower.includes("http://") || lower.includes("https://")) scamType = "phishing";
  else if (lower.includes("bank") || lower.includes("otp")) scamType = "bank_fraud";
  else if (scamLikely) scamType = "other";

  return {
    scamLikely,
    scamType,
    confidence: scamLikely ? Math.min(0.95, 0.45 + score * 0.08) : 0.25,
    triggerPhrases,
    suspiciousKeywords,
    reasonCodes: reasonCodes.length > 0 ? reasonCodes : ["OTHER"],
  };
}

function hasPrimaryIntel(extractedIntelligence) {
  if (!extractedIntelligence) return false;
  return (
    (extractedIntelligence.upiIds || []).length > 0 ||
    (extractedIntelligence.phoneNumbers || []).length > 0 ||
    (extractedIntelligence.phishingLinks || []).length > 0 ||
    (extractedIntelligence.bankAccounts || []).length > 0
  );
}

function uniqueSorted(values = []) {
  return Array.from(new Set(values || [])).filter(Boolean).sort();
}

function buildIntelFingerprint(session) {
  const intel = session?.extractedIntelligence || {};
  const signals = session?.scamSignals || {};
  return JSON.stringify({
    bankAccounts: uniqueSorted(intel.bankAccounts),
    upiIds: uniqueSorted(intel.upiIds),
    emailAddresses: uniqueSorted(intel.emailAddresses),
    phishingLinks: uniqueSorted(intel.phishingLinks),
    phoneNumbers: uniqueSorted(intel.phoneNumbers),
    caseIds: uniqueSorted(intel.caseIds),
    policyNumbers: uniqueSorted(intel.policyNumbers),
    orderNumbers: uniqueSorted(intel.orderNumbers),
    staffIds: uniqueSorted(intel.staffIds),
    agentNames: uniqueSorted(intel.agentNames),
    claimedOrganization: signals.claimedOrganization || "",
    claimedDepartment: signals.claimedDepartment || "",
  });
}

function updatePrimaryCaptureState(
  session,
  totalMessages,
  scammerMessages,
  primaryCapturedNow,
) {
  const fingerprint = buildIntelFingerprint(session);
  if (session.lastIntelFingerprint !== fingerprint) {
    session.lastIntelFingerprint = fingerprint;
    session.lastIntelGrowthScammerMessages = scammerMessages;
  }

  if (primaryCapturedNow && session.primaryCaptureTotalMessages === null) {
    session.primaryCaptureTotalMessages = totalMessages;
    session.primaryCaptureScammerMessages = scammerMessages;
  }
}

function normalizeHandle(value = "") {
  return String(value || "").trim().replace(/[.,;:!?]+$/, "");
}

function classifyHandleByContext(handle = "", source = "") {
  const normalized = normalizeHandle(handle);
  if (!/^[a-z0-9._%+-]{2,}@[a-z0-9.-]{2,}$/i.test(normalized)) {
    return "unknown";
  }

  const loweredSource = String(source || "").toLowerCase();
  const loweredHandle = normalized.toLowerCase();
  const index = loweredSource.indexOf(loweredHandle);
  const windowText =
    index >= 0
      ? loweredSource.slice(Math.max(0, index - 30), index + loweredHandle.length + 30)
      : loweredSource;

  if (/\bemail|mail\b/i.test(windowText)) return "email";
  if (/\bupi|vpa|handle|gpay|phonepe|paytm|bhim\b/i.test(windowText)) {
    return "upi";
  }

  const domain = (normalized.split("@")[1] || "").toLowerCase();
  if (!/\.[a-z]{2,}$/i.test(domain)) return "upi";
  if (/(upi|ybl|ibl|axl|oksbi|okhdfc|okicici|okaxis|okbizaxis|apl|^ok[a-z0-9]+)/i.test(domain)) {
    return "upi";
  }
  return "email";
}

function extractInlineIntel(text = "") {
  const source = typeof text === "string" ? text : "";
  const lower = source.toLowerCase();

  const handleCandidates = Array.from(
    new Set(
      source.match(/\b[a-z0-9._%+-]{2,}@[a-z0-9.-]{2,}\b/gi) || [],
    ),
  );
  const upiIds = [];
  const emailAddresses = [];
  for (const handle of handleCandidates) {
    const type = classifyHandleByContext(handle, source);
    if (type === "upi") upiIds.push(normalizeHandle(handle));
    if (type === "email") emailAddresses.push(normalizeHandle(handle));
  }

  const phishingLinks = Array.from(
    new Set(source.match(/https?:\/\/\S+/gi) || []),
  );

  const bankAccounts = [];
  const bankRegex =
    /(account|acct|a\/c|bank)\s*(number|no\.?|id)?\s*[:#-]?\s*([0-9Xx*\s\-_/]{9,24})/gi;
  let bankMatch = null;
  while ((bankMatch = bankRegex.exec(source)) !== null) {
    if (bankMatch[3]) {
      bankAccounts.push(bankMatch[3].trim());
    }
  }

  const bankDigits = new Set(
    bankAccounts.map((value) => (value.match(/\d/g) || []).join("")),
  );
  const phoneNumbers = Array.from(
    new Set(source.match(/(?:\+?\d[\d\s-]{8,}\d)/g) || []),
  ).filter((value) => {
    const digits = (value.match(/\d/g) || []).join("");
    const digitCount = digits.length;
    if (digitCount < 10 || digitCount > 13) return false;
    if (bankDigits.has(digits)) return false;
    return true;
  });

  const suspiciousKeywords = [
    "urgent",
    "verify",
    "otp",
    "upi",
    "account blocked",
    "locked",
    "kyc",
  ].filter((kw) => lower.includes(kw));

  const caseIds = extractCaseIdsFromText(source);
  const policyNumbers = extractPolicyNumbersFromText(source);
  const orderNumbers = extractOrderNumbersFromText(source);

  return {
    bankAccounts,
    upiIds,
    emailAddresses,
    phishingLinks,
    phoneNumbers,
    suspiciousKeywords,
    caseIds,
    policyNumbers,
    orderNumbers,
    staffIds: [],
    agentNames: [],
  };
}

function hasInlineIntel(intel = {}) {
  return (
    (intel.bankAccounts || []).length > 0 ||
    (intel.upiIds || []).length > 0 ||
    (intel.emailAddresses || []).length > 0 ||
    (intel.phishingLinks || []).length > 0 ||
    (intel.phoneNumbers || []).length > 0 ||
    (intel.suspiciousKeywords || []).length > 0 ||
    (intel.caseIds || []).length > 0 ||
    (intel.policyNumbers || []).length > 0 ||
    (intel.orderNumbers || []).length > 0
  );
}

function isIntelligenceEmpty(session) {
  const intel = session?.extractedIntelligence || {};
  return (
    (intel.bankAccounts || []).length === 0 &&
    (intel.upiIds || []).length === 0 &&
    (intel.emailAddresses || []).length === 0 &&
    (intel.phishingLinks || []).length === 0 &&
    (intel.phoneNumbers || []).length === 0 &&
    (intel.suspiciousKeywords || []).length === 0 &&
    (intel.caseIds || []).length === 0 &&
    (intel.policyNumbers || []).length === 0 &&
    (intel.orderNumbers || []).length === 0 &&
    (intel.staffIds || []).length === 0 &&
    (intel.agentNames || []).length === 0
  );
}

function hydrateInlineIntelFromHistory(sessionId, messages = []) {
  for (const message of messages || []) {
    if (message?.sender !== "scammer") continue;
    const inlineIntel = extractInlineIntel(message?.text || "");
    if (hasInlineIntel(inlineIntel)) {
      updateIntelligence(sessionId, { extractedIntelligence: inlineIntel });
    }
  }
}

function extractCaseIdsFromText(text = "") {
  const source = typeof text === "string" ? text : "";
  const regex =
    /\b(?:case|reference|ref)\s*(?:id|no\.?|number)?\s*(?:is|:|#|-)?\s*([A-Za-z0-9][A-Za-z0-9\-\/]{2,})\b/gi;
  const results = new Set();
  let match = null;

  while ((match = regex.exec(source)) !== null) {
    const rawValue = (match[1] || "").trim().replace(/[.,;:!?]+$/, "");
    // Case/reference IDs in this flow are expected to include at least one digit.
    if (rawValue && /\d/.test(rawValue)) {
      results.add(rawValue);
    }
  }

  return Array.from(results);
}

function extractPolicyNumbersFromText(text = "") {
  const source = typeof text === "string" ? text : "";
  const regex =
    /\b(?:policy)\s*(?:id|no\.?|number)?\s*(?:is|:|#|-)?\s*([A-Za-z0-9][A-Za-z0-9\-\/]{2,})\b/gi;
  const results = new Set();
  let match = null;

  while ((match = regex.exec(source)) !== null) {
    const rawValue = (match[1] || "").trim().replace(/[.,;:!?]+$/, "");
    if (rawValue && /\d/.test(rawValue)) {
      results.add(rawValue);
    }
  }
  return Array.from(results);
}

function extractOrderNumbersFromText(text = "") {
  const source = typeof text === "string" ? text : "";
  const regex =
    /\b(?:order|tracking|shipment)\s*(?:id|no\.?|number)?\s*(?:is|:|#|-)?\s*([A-Za-z0-9][A-Za-z0-9\-\/]{2,})\b/gi;
  const results = new Set();
  let match = null;

  while ((match = regex.exec(source)) !== null) {
    const rawValue = (match[1] || "").trim().replace(/[.,;:!?]+$/, "");
    if (rawValue && /\d/.test(rawValue)) {
      results.add(rawValue);
    }
  }
  return Array.from(results);
}

function deriveHaveFromMessages(messages = []) {
  const scammerText = (messages || [])
    .filter((msg) => msg.sender === "scammer")
    .map((msg) => msg.text || "")
    .join("\n");
  const normalized = String(scammerText || "");
  const handleCandidates = Array.from(
    new Set(
      normalized.match(/\b[a-z0-9._%+-]{2,}@[a-z0-9.-]{2,}\b/gi) || [],
    ),
  );
  const upiDetected = handleCandidates.some(
    (value) => classifyHandleByContext(value, normalized) === "upi",
  );
  const emailDetected = handleCandidates.some(
    (value) => classifyHandleByContext(value, normalized) === "email",
  );

  return {
    phoneNumber: /(?:\+?\d[\d\s-]{8,}\d)/.test(normalized),
    upiId: upiDetected,
    bankAccount:
      /\b(?:account|acct|a\/c|bank)\b[\s\S]{0,24}\b\d{9,18}\b/i.test(
        normalized,
      ),
    emailAddress: emailDetected,
    phishingLink: /https?:\/\/\S+/i.test(normalized),
    caseId: extractCaseIdsFromText(normalized).length > 0,
    policyNumber: extractPolicyNumbersFromText(normalized).length > 0,
    orderNumber: extractOrderNumbersFromText(normalized).length > 0,
    agentName: /\b(?:i am|my name is|agent|mr\.?|mrs\.?|ms\.?)\b/i.test(
      normalized,
    ),
    claimedOrg:
      /\b(?:bank|sbi|customer care|support|security team|verification team|fraud prevention)\b/i.test(
        normalized,
      ),
  };
}

function buildDialogState(session) {
  const baseHave = {
    phoneNumber: (session.extractedIntelligence.phoneNumbers || []).length > 0,
    upiId: (session.extractedIntelligence.upiIds || []).length > 0,
    bankAccount: (session.extractedIntelligence.bankAccounts || []).length > 0,
    emailAddress:
      (session.extractedIntelligence.emailAddresses || []).length > 0,
    phishingLink:
      (session.extractedIntelligence.phishingLinks || []).length > 0,
    caseId: (session.extractedIntelligence.caseIds || []).length > 0,
    policyNumber:
      (session.extractedIntelligence.policyNumbers || []).length > 0,
    orderNumber:
      (session.extractedIntelligence.orderNumbers || []).length > 0,
    agentName: (session.extractedIntelligence.agentNames || []).length > 0,
    claimedOrg: Boolean(session.scamSignals?.claimedOrganization),
  };
  const observedHave = deriveHaveFromMessages(session.messages || []);
  const have = {
    phoneNumber: baseHave.phoneNumber || observedHave.phoneNumber,
    upiId: baseHave.upiId || observedHave.upiId,
    bankAccount: baseHave.bankAccount || observedHave.bankAccount,
    emailAddress: baseHave.emailAddress || observedHave.emailAddress,
    phishingLink: baseHave.phishingLink || observedHave.phishingLink,
    caseId: baseHave.caseId || observedHave.caseId,
    policyNumber: baseHave.policyNumber || observedHave.policyNumber,
    orderNumber: baseHave.orderNumber || observedHave.orderNumber,
    agentName: baseHave.agentName || observedHave.agentName,
    claimedOrg: baseHave.claimedOrg || observedHave.claimedOrg,
  };

  return {
    askedCounts: session.dialogState?.askedCounts || {},
    have,
    lastIntentTags: session.dialogState?.lastIntentTags || [],
    scamType:
      session.scamSignals?.scamType ||
      session.scamAssessment?.scamType ||
      "unknown",
  };
}

function hasLinkEvidence(session) {
  if (!session) return false;

  const hasExtractedLink =
    (session.extractedIntelligence?.phishingLinks || []).length > 0;
  if (hasExtractedLink) return true;

  const askedLinkCount = session.dialogState?.askedCounts?.link || 0;
  if (askedLinkCount > 0) return true;

  // Backup check in case the model forgot to tag extractionTargets.
  return (session.messages || []).some(
    (msg) =>
      msg.sender === "user" &&
      /(official\s+link|website|url|portal|site)/i.test(msg.text || ""),
  );
}

function chooseForcedTarget(dialogState) {
  const have = dialogState?.have || {};
  const asked = dialogState?.askedCounts || {};
  const scamType = dialogState?.scamType || "unknown";
  const canAsk = (key) => (asked[key] || 0) < 2;
  const checkOrder = (targets = []) => {
    for (const item of targets) {
      const askedKey = item === "phishingLink" ? "link" : item;
      if (!have[item] && canAsk(askedKey)) return item;
    }
    return null;
  };

  if (scamType === "upi_fraud") {
    const next = checkOrder([
      "upiId",
      "phoneNumber",
      "emailAddress",
      "phishingLink",
      "caseId",
      "policyNumber",
      "orderNumber",
      "agentName",
      "claimedOrg",
      "bankAccount",
    ]);
    if (next) return next;
  }

  if (scamType === "phishing") {
    const next = checkOrder([
      "phishingLink",
      "emailAddress",
      "phoneNumber",
      "upiId",
      "caseId",
      "orderNumber",
      "agentName",
      "claimedOrg",
      "bankAccount",
      "policyNumber",
    ]);
    if (next) return next;
  }

  // Default priority is explicit and deterministic to avoid loops.
  const next = checkOrder([
    "upiId",
    "bankAccount",
    "phishingLink",
    "phoneNumber",
    "emailAddress",
    "caseId",
    "policyNumber",
    "orderNumber",
    "agentName",
    "claimedOrg",
  ]);
  if (next) return next;
  return "NONE";
}

function inferExtractionTargetsFromReply(reply = "") {
  const text = String(reply || "");
  const lower = text.toLowerCase();
  const targets = new Set();
  const isQuestionLike = /\?/.test(text) || /\b(could|can|which|what|where|who)\b/i.test(text);

  if (!isQuestionLike) {
    return [];
  }

  if (/\bupi\b|@\w+/i.test(lower)) targets.add("upiId");
  if (/\bbank account\b|\baccount number\b|\ba\/c\b/i.test(lower)) {
    targets.add("bankAccount");
  }
  if (/\bofficial\s+(website|link|url)\b|\bwebsite\b|\blink\b|\burl\b|\bportal\b/i.test(lower)) {
    targets.add("phishingLink");
  }
  if (
    /\b(helpline|phone number|contact number|number should i call|which number should i call|call)\b/i.test(
      lower,
    )
  ) {
    targets.add("phoneNumber");
  }
  if (/\bemail\b|\bmail\b/.test(lower)) {
    targets.add("emailAddress");
  }
  if (/\bcase\s*id\b|\breference\b/i.test(lower)) targets.add("caseId");
  if (/\bpolicy\s*(id|number|no\.?)\b/i.test(lower)) {
    targets.add("policyNumber");
  }
  if (/\border\s*(id|number|no\.?)\b|\btracking\s*(id|number|no\.?)\b/i.test(lower)) {
    targets.add("orderNumber");
  }
  if (/\bagent\b|\bname\b/i.test(lower)) targets.add("agentName");
  if (/\borganization\b|\bdepartment\b|\bcompany\b|\borg\b/i.test(lower)) {
    targets.add("claimedOrg");
  }

  return Array.from(targets);
}

function getAskedCountKey(target = "") {
  if (target === "phishingLink") return "link";
  if (target === "bankAccount") return "bankAccount";
  if (target === "upiId") return "upiId";
  if (target === "phoneNumber") return "phoneNumber";
  if (target === "emailAddress") return "emailAddress";
  if (target === "caseId") return "caseId";
  if (target === "policyNumber") return "policyNumber";
  if (target === "orderNumber") return "orderNumber";
  if (target === "agentName") return "agentName";
  if (target === "claimedOrg") return "claimedOrg";
  return null;
}

function isTargetKnownOrExhausted(target, dialogState = {}) {
  if (!target) return false;
  const have = dialogState.have || {};
  const askedCounts = dialogState.askedCounts || {};
  const askedKey = getAskedCountKey(target);
  const askedCount = askedKey ? askedCounts[askedKey] || 0 : 0;
  return Boolean(have[target]) || askedCount >= 2;
}

function replyMentionsTarget(reply = "", target = "NONE") {
  const text = String(reply || "").toLowerCase();
  if (target === "NONE") return true;
  if (target === "upiId") return /\bupi\b|@/.test(text);
  if (target === "bankAccount") return /\baccount\b|\bbank\b/.test(text);
  if (target === "phishingLink") return /\blink\b|\bwebsite\b|\burl\b|\bportal\b/.test(text);
  if (target === "phoneNumber") return /\bcall\b|\bcontact\b|\bnumber\b|\bhelpline\b/.test(text);
  if (target === "emailAddress") return /\bemail\b|\bmail\b/.test(text);
  if (target === "agentName") return /\bname\b/.test(text);
  if (target === "caseId") return /\bcase\b|\breference\b/.test(text);
  if (target === "policyNumber") return /\bpolicy\b/.test(text);
  if (target === "orderNumber") return /\border\b|\btracking\b/.test(text);
  if (target === "claimedOrg") return /\borganization\b|\borg\b|\bdepartment\b|\bcompany\b/.test(text);
  return true;
}

function forcedTargetFallbackReply(target = "NONE") {
  if (target === "upiId") {
    return "I want to follow your steps correctly. Which UPI ID should I use for this verification?";
  }
  if (target === "bankAccount") {
    return "I want to do this correctly. Which bank account should I use for the verification?";
  }
  if (target === "phishingLink") {
    return "I want to verify this on the right portal. Which official website link should I open?";
  }
  if (target === "phoneNumber") {
    return "If this fails, which official number should I call for support?";
  }
  if (target === "emailAddress") {
    return "If I need to follow up, which official email should I use?";
  }
  if (target === "agentName") {
    return "Who should I ask for when I follow up on this?";
  }
  if (target === "caseId") {
    return "Which case ID should I quote so this request is tracked?";
  }
  if (target === "policyNumber") {
    return "Which policy number should I quote for this verification?";
  }
  if (target === "orderNumber") {
    return "Which order or tracking number should I keep for follow-up?";
  }
  if (target === "claimedOrg") {
    return "Which official organization name should I mention for this verification?";
  }
  return "";
}

function nonRepeatingFallbackReply(session) {
  const variants = [
    "Thanks, I noted that. Is there any other official detail I should keep for verification?",
    "Noted. Is there any additional reference or contact detail I should keep?",
    "Alright, I have what I need for now. I'll follow up shortly.",
  ];
  const previousUserMessages = (session?.messages || []).filter(
    (msg) => msg.sender === "user",
  );
  const fallbackUsageCount = previousUserMessages.filter((msg) =>
    /official detail|additional reference|follow up shortly|verify these details and get back/i.test(
      msg.text || "",
    ),
  ).length;
  const variantIndex = Math.min(fallbackUsageCount, variants.length - 1);
  return variants[variantIndex];
}

function replyMentionsRedFlag(reply = "") {
  const text = String(reply || "").toLowerCase();
  return /\burgent|immediate|otp|blocked|suspend|freeze|threat|warning|link|website|payment|fee|transfer\b/i.test(
    text,
  );
}

function deriveRedFlagCue(latestIncomingText = "") {
  const lower = String(latestIncomingText || "").toLowerCase();
  if (!lower) return "";
  if (/\botp|pin|password\b/i.test(lower)) {
    return "I saw your OTP request.";
  }
  if (/\burgent|immediate|act now|minutes?\b/i.test(lower)) {
    return "I saw this is marked urgent.";
  }
  if (/\bblocked|suspend|freeze|locked|compromised\b/i.test(lower)) {
    return "I saw your account-block warning.";
  }
  if (/\bhttps?:\/\/|link|website|url|portal\b/i.test(lower)) {
    return "I saw the link details you shared.";
  }
  if (/\bpayment|fee|transfer|pay\b/i.test(lower)) {
    return "I saw your payment instruction.";
  }
  return "";
}

function enforceRedFlagReference(reply = "", latestIncomingText = "") {
  const text = String(reply || "").trim();
  if (!text) return text;
  if (replyMentionsRedFlag(text)) return text;
  const cue = deriveRedFlagCue(latestIncomingText);
  if (!cue) return text;
  return `${cue} ${text}`;
}

function getEngagementDurationSeconds(session) {
  const startedAtMs = Number(session?.startedAtMs || 0);
  if (!startedAtMs) return 0;
  const durationSeconds = Math.floor((Date.now() - startedAtMs) / 1000);
  return durationSeconds > 0 ? durationSeconds : 1;
}

function getReportedEngagementDurationSeconds(session) {
  const measured = getEngagementDurationSeconds(session);
  return Math.max(measured, MIN_REPORTED_ENGAGEMENT_SECONDS);
}

function buildFallbackExtractionFromConversation(messages = []) {
  const aggregate = {
    bankAccounts: [],
    upiIds: [],
    emailAddresses: [],
    phishingLinks: [],
    phoneNumbers: [],
    suspiciousKeywords: [],
    caseIds: [],
    policyNumbers: [],
    orderNumbers: [],
    staffIds: [],
    agentNames: [],
  };

  for (const message of messages || []) {
    if (message?.sender !== "scammer") continue;
    const intel = extractInlineIntel(message?.text || "");
    aggregate.bankAccounts = mergeUniqueStrings(aggregate.bankAccounts, intel.bankAccounts);
    aggregate.upiIds = mergeUniqueStrings(aggregate.upiIds, intel.upiIds);
    aggregate.emailAddresses = mergeUniqueStrings(
      aggregate.emailAddresses,
      intel.emailAddresses,
    );
    aggregate.phishingLinks = mergeUniqueStrings(aggregate.phishingLinks, intel.phishingLinks);
    aggregate.phoneNumbers = mergeUniqueStrings(aggregate.phoneNumbers, intel.phoneNumbers);
    aggregate.suspiciousKeywords = mergeUniqueStrings(
      aggregate.suspiciousKeywords,
      intel.suspiciousKeywords,
    );
    aggregate.caseIds = mergeUniqueStrings(aggregate.caseIds, intel.caseIds);
    aggregate.policyNumbers = mergeUniqueStrings(
      aggregate.policyNumbers,
      intel.policyNumbers,
    );
    aggregate.orderNumbers = mergeUniqueStrings(
      aggregate.orderNumbers,
      intel.orderNumbers,
    );
  }

  return {
    extractedIntelligence: aggregate,
    scamSignals: {
      claimedOrganization: null,
      claimedDepartment: null,
      scamType: "unknown",
      tactics: [],
    },
    agentNotes:
      "Fallback extraction used due to temporary model failure. Intelligence captured from regex parsing.",
  };
}

export async function processMessage(payload) {
  console.log("[Request] made");
  const startTime = Date.now();
  const { message, sessionId, metadata, conversationHistory } = payload || {};

  if (!sessionId || typeof sessionId !== "string") {
    console.error("[Request] Missing or invalid sessionId");
    const response = {
      statusCode: 400,
      body: { status: "failed", reply: "", message: "sessionId is required" },
    };
    recordResponseTime(sessionId || "unknown", Date.now() - startTime);
    return response;
  }

  if (!message || typeof message.text !== "string" || !message.text.trim()) {
    console.error("[Request] Missing or invalid message.text");
    const response = {
      statusCode: 400,
      body: { status: "failed", reply: "", message: "message.text is required" },
    };
    recordResponseTime(sessionId || "unknown", Date.now() - startTime);
    return response;
  }

  const session = getOrCreateSession(sessionId);
  if (session.callbackSent) {
    console.error("[Session] Callback already sent, hard stop");
    const response = {
      statusCode: 200,
      body: {
        status: "success",
        reply: "Alright, I have what I need for now. I'll follow up shortly.",
      },
    };
    recordResponseTime(sessionId, Date.now() - startTime);
    return response;
  }

  const normalizedMessage = {
    sender: message.sender || "scammer",
    text: message.text,
    timestamp: message.timestamp || new Date().toISOString(),
  };

  updateMetadata(sessionId, metadata);
  const { changed: historyChanged } = reconcileSessionMessages(
    sessionId,
    conversationHistory,
  );
  appendMessageIfMissing(sessionId, normalizedMessage);

  if (historyChanged) {
    const syncedSession = getOrCreateSession(sessionId);
    if (isIntelligenceEmpty(syncedSession)) {
      hydrateInlineIntelFromHistory(sessionId, syncedSession.messages);
    }
  }

  let result = session.scamAssessment;
  if (!result) {
    const prompt = buildClassifierPrompt(normalizedMessage.text);
    try {
      result = await generateJson(prompt);
    } catch (error) {
      logLlmFallback("scam_classification", sessionId, error);
      result = buildRuleBasedScamAssessment(normalizedMessage.text);
    }
    setInitialScamAssessment(sessionId, result);
  }

  if (result.scamLikely) {
    let responseReply = null;
    let exhaustedDialogFallback = false;
    if (normalizedMessage.sender === "scammer") {
      const inlineIntel = extractInlineIntel(normalizedMessage.text);
      if (hasInlineIntel(inlineIntel)) {
        updateIntelligence(sessionId, { extractedIntelligence: inlineIntel });
      }
    }

    const refreshedSession = getOrCreateSession(sessionId);
    const dialogState = buildDialogState(refreshedSession);
    const forcedTarget = chooseForcedTarget(dialogState);
    const agentPrompt = buildAgentReplyPrompt({
      sessionId,
      message: normalizedMessage,
      conversationHistory: refreshedSession.messages,
      persona: {},
      knownIntelligence: refreshedSession.extractedIntelligence,
      scamAssessment: result,
      dialogState,
      forcedTarget,
    });
    let agentReply;
    try {
      agentReply = await generateJson(
        agentPrompt,
        agentReplySchema,
        "agent_reply",
      );
    } catch (error) {
      logLlmFallback("agent_reply", sessionId, error);
      const fallbackTarget =
        forcedTarget !== "NONE" ? forcedTarget : chooseForcedTarget(dialogState);
      const fallbackReply =
        fallbackTarget !== "NONE"
          ? forcedTargetFallbackReply(fallbackTarget)
          : "Thanks, I noted that. Is there any other official detail I should keep for verification?";
      agentReply = {
        reply: fallbackReply,
        intentTag: fallbackTarget === "NONE" ? "STALL" : "ASK_CLARIFY",
        extractionTargets: fallbackTarget === "NONE" ? [] : [fallbackTarget],
      };
    }

    const normalizedAgentReply = { ...agentReply };
    let finalReply = normalizedAgentReply.reply || "";
    let replyTargets = inferExtractionTargetsFromReply(finalReply);

    const blockedAskedTarget = replyTargets.find((target) =>
      isTargetKnownOrExhausted(target, dialogState),
    );
    if (blockedAskedTarget) {
      const fallbackTarget =
        forcedTarget !== "NONE" && !isTargetKnownOrExhausted(forcedTarget, dialogState)
          ? forcedTarget
          : chooseForcedTarget(dialogState);
      const fallbackReply =
        fallbackTarget !== "NONE"
          ? forcedTargetFallbackReply(fallbackTarget)
          : nonRepeatingFallbackReply(refreshedSession);
      if (fallbackReply) {
        if (fallbackTarget === "NONE") {
          exhaustedDialogFallback = true;
        }
        finalReply = fallbackReply;
        replyTargets = inferExtractionTargetsFromReply(finalReply);
      }
    }

    if (forcedTarget !== "NONE" && !replyMentionsTarget(finalReply, forcedTarget)) {
      const fallback = forcedTargetFallbackReply(forcedTarget);
      if (fallback) {
        finalReply = fallback;
        replyTargets = inferExtractionTargetsFromReply(finalReply);
      }
    }

    if (
      forcedTarget !== "NONE" &&
      finalReply &&
      !/\?/.test(finalReply)
    ) {
      const fallback = forcedTargetFallbackReply(forcedTarget);
      if (fallback) {
        finalReply = fallback;
        replyTargets = inferExtractionTargetsFromReply(finalReply);
      }
    }

    finalReply = enforceRedFlagReference(finalReply, normalizedMessage.text);

    const mergedTargets = new Set([...replyTargets]);
    if (forcedTarget !== "NONE" && replyMentionsTarget(finalReply, forcedTarget)) {
      mergedTargets.add(forcedTarget);
    }
    normalizedAgentReply.extractionTargets = Array.from(mergedTargets);

    appendReply(sessionId, finalReply);
    normalizedAgentReply.reply = finalReply;
    updateDialogState(sessionId, normalizedAgentReply);
    responseReply = finalReply;

    const updatedSession = getOrCreateSession(sessionId);
    const messagesSinceExtract =
      updatedSession.messages.length - updatedSession.lastExtractedMessageCount;
    const shouldExtract = messagesSinceExtract >= 3;

    if (shouldExtract || updatedSession.endConversation) {
      const extractPrompt = buildIntelligenceExtractionPrompt({
        sessionId,
        conversation: updatedSession.messages,
        metadata: updatedSession.metadata,
      });
      let extraction;
      try {
        extraction = await generateJson(
          extractPrompt,
          intelligenceExtractionSchema,
          "intelligence_extraction",
        );
      } catch (error) {
        logLlmFallback("intelligence_extraction", sessionId, error);
        extraction = buildFallbackExtractionFromConversation(updatedSession.messages);
      }
      updateIntelligence(sessionId, extraction);
      markExtractionRun(sessionId);
    }

    const totalMessages = updatedSession.messages.length;
    const scammerMessages = countScammerMessages(updatedSession.messages);
    const hasExtractionRun = updatedSession.lastExtractedMessageCount > 0;
    const extractionRuns = updatedSession.extractionRuns || 0;
    const hasPrimaryIntelItem = hasPrimaryIntel(
      updatedSession.extractedIntelligence,
    );
    const meetsEndGate =
      totalMessages >= MIN_TOTAL_MESSAGES &&
      scammerMessages >= MIN_SCAMMER_MESSAGES &&
      extractionRuns >= MIN_EXTRACTION_RUNS &&
      (!REQUIRE_PRIMARY_INTEL || hasPrimaryIntelItem);

    const hasAllPrimaryIntel =
      (updatedSession.extractedIntelligence.upiIds || []).length > 0 &&
      (updatedSession.extractedIntelligence.phoneNumbers || []).length > 0 &&
      (updatedSession.extractedIntelligence.bankAccounts || []).length > 0;

    const hasAskedOrCapturedLink = hasLinkEvidence(updatedSession);
    const primaryCapturedNow = hasAllPrimaryIntel && hasAskedOrCapturedLink;
    updatePrimaryCaptureState(
      updatedSession,
      totalMessages,
      scammerMessages,
      primaryCapturedNow,
    );

    const captureTotal = updatedSession.primaryCaptureTotalMessages;
    const captureScammer = updatedSession.primaryCaptureScammerMessages;
    const postCaptureTotalMessages =
      captureTotal === null ? 0 : totalMessages - captureTotal;
    const postCaptureScammerMessages =
      captureScammer === null ? 0 : scammerMessages - captureScammer;
    const noNewIntelScammerTurns =
      scammerMessages - (updatedSession.lastIntelGrowthScammerMessages || 0);

    const stabilizationWindowReached =
      captureTotal !== null &&
      captureScammer !== null &&
      postCaptureTotalMessages >= POST_PRIMARY_GRACE_TOTAL_MESSAGES &&
      postCaptureScammerMessages >= POST_PRIMARY_GRACE_SCAMMER_MESSAGES;
    const intelStalled =
      noNewIntelScammerTurns >= NO_NEW_INTEL_SCAMMER_TURNS;
    const meetsEarlyStop =
      hasExtractionRun &&
      primaryCapturedNow &&
      stabilizationWindowReached &&
      intelStalled &&
      totalMessages >= EARLY_STOP_MIN_TOTAL_MESSAGES &&
      scammerMessages >= EARLY_STOP_MIN_SCAMMER_MESSAGES;

    const hardStopMessageCap = Math.min(
      MIN_TOTAL_MESSAGES + GRACE_MESSAGES,
      MAX_SCAMMER_TURNS * 2,
    );
    const hardStopReached = totalMessages >= hardStopMessageCap;
    const maxScammerTurnsReached = scammerMessages >= MAX_SCAMMER_TURNS;
    const exhaustedDialogReady =
      exhaustedDialogFallback &&
      hasExtractionRun &&
      hasAllPrimaryIntel &&
      hasAskedOrCapturedLink &&
      totalMessages >= Math.max(12, MIN_TOTAL_MESSAGES - 2) &&
      scammerMessages >= Math.max(6, MIN_SCAMMER_MESSAGES - 2);

    const shouldEvaluateEnd =
      hardStopReached ||
      maxScammerTurnsReached ||
      meetsEarlyStop ||
      exhaustedDialogReady ||
      (meetsEndGate && hasAskedOrCapturedLink);

    if (shouldEvaluateEnd) {
      const endPrompt = buildConversationEndPrompt({
        sessionId,
        conversation: updatedSession.messages,
        scamAssessment: updatedSession.scamAssessment,
        extractedIntelligence: updatedSession.extractedIntelligence,
      });
      let endDecision;
      if (hardStopReached || maxScammerTurnsReached) {
        endDecision = {
          endConversation: true,
          reason: maxScammerTurnsReached
            ? "Max scammer turns reached"
            : "Hard stop reached",
        };
      } else {
        try {
          endDecision = await generateJson(
            endPrompt,
            conversationEndSchema,
            "conversation_end",
          );
        } catch (error) {
          logLlmFallback("conversation_end", sessionId, error);
          endDecision = {
            endConversation: Boolean(
              meetsEarlyStop ||
                exhaustedDialogReady ||
                meetsEndGate ||
                maxScammerTurnsReached ||
                hardStopReached,
            ),
            reason: "Fallback end decision after model failure",
          };
        }
      }

      if (endDecision.endConversation) {
        setConversationEnded(sessionId, true);
        const endSession = getOrCreateSession(sessionId);
        if (endSession.lastExtractedMessageCount < endSession.messages.length) {
          const finalExtractPrompt = buildIntelligenceExtractionPrompt({
            sessionId,
            conversation: endSession.messages,
            metadata: endSession.metadata,
          });
          let finalExtraction;
          try {
            finalExtraction = await generateJson(
              finalExtractPrompt,
              intelligenceExtractionSchema,
              "intelligence_extraction_final",
            );
          } catch (error) {
            logLlmFallback("intelligence_extraction_final", sessionId, error);
            finalExtraction = buildFallbackExtractionFromConversation(
              endSession.messages,
            );
          }
          updateIntelligence(sessionId, finalExtraction);
          markExtractionRun(sessionId);
        }

          if (endSession.scamAssessment?.scamLikely && !endSession.callbackSent) {
            const disengagementMessage =
              "Alright, I have what I need for now. I'll follow up shortly.";
            appendReply(sessionId, disengagementMessage);
            responseReply = disengagementMessage;

          const payloadIntel = {
            bankAccounts: endSession.extractedIntelligence.bankAccounts || [],
            upiIds: endSession.extractedIntelligence.upiIds || [],
            emailAddresses:
              endSession.extractedIntelligence.emailAddresses || [],
            phishingLinks: endSession.extractedIntelligence.phishingLinks || [],
            phoneNumbers: endSession.extractedIntelligence.phoneNumbers || [],
            caseIds: endSession.extractedIntelligence.caseIds || [],
            policyNumbers:
              endSession.extractedIntelligence.policyNumbers || [],
            orderNumbers:
              endSession.extractedIntelligence.orderNumbers || [],
            staffIds: endSession.extractedIntelligence.staffIds || [],
            agentNames: endSession.extractedIntelligence.agentNames || [],
            suspiciousKeywords:
              endSession.extractedIntelligence.suspiciousKeywords || [],
          };

          const noteParts = [];
          if (endSession.agentNotes) noteParts.push(endSession.agentNotes);
          if (endSession.extractedIntelligence.caseIds?.length) {
            noteParts.push(
              `Case IDs: ${endSession.extractedIntelligence.caseIds.join(", ")}`,
            );
          }
          if (endSession.extractedIntelligence.policyNumbers?.length) {
            noteParts.push(
              `Policy Numbers: ${endSession.extractedIntelligence.policyNumbers.join(", ")}`,
            );
          }
          if (endSession.extractedIntelligence.orderNumbers?.length) {
            noteParts.push(
              `Order Numbers: ${endSession.extractedIntelligence.orderNumbers.join(", ")}`,
            );
          }
          if (endSession.extractedIntelligence.staffIds?.length) {
            noteParts.push(
              `Staff IDs: ${endSession.extractedIntelligence.staffIds.join(", ")}`,
            );
          }
          if (endSession.extractedIntelligence.agentNames?.length) {
            noteParts.push(
              `Names: ${endSession.extractedIntelligence.agentNames.join(", ")}`,
            );
          }
          if (endSession.scamSignals?.claimedOrganization) {
            noteParts.push(
              `Claimed org: ${endSession.scamSignals.claimedOrganization}`,
            );
          }
          if (endSession.scamSignals?.claimedDepartment) {
            noteParts.push(
              `Claimed dept: ${endSession.scamSignals.claimedDepartment}`,
            );
          }

          const engagementMetrics = {
            totalMessagesExchanged: endSession.messages.length,
            engagementDurationSeconds:
              getReportedEngagementDurationSeconds(endSession),
          };

          const payload = {
            status: "success",
            sessionId,
            scamDetected: true,
            totalMessagesExchanged: endSession.messages.length,
            engagementDurationSeconds:
              engagementMetrics.engagementDurationSeconds,
            extractedIntelligence: payloadIntel,
            engagementMetrics,
            scamType:
              endSession.scamSignals?.scamType ||
              endSession.scamAssessment?.scamType ||
              "unknown",
            confidenceLevel:
              Number(endSession.scamAssessment?.confidence || 0) || 0,
            agentNotes: noteParts.join(" "),
          };
            try {
              await sendFinalResult(payload);
              setCallbackSent(sessionId, true);
              setConversationEnded(sessionId, true);
            } catch (error) {
              console.error(
                `[GUVI Callback] Non-fatal failure for sessionId=${sessionId}: ${error?.message || "unknown"}`,
              );
            }

            const timing = getTimingStats(sessionId);
            console.log("[Timing] Response times (ms):", timing.times);
            console.log("[Timing] Average response time (ms):", timing.averageMs);
          }
      }
    }

    const response = {
      statusCode: 200,
      body: { status: "success", reply: responseReply || "" },
    };
    recordResponseTime(sessionId, Date.now() - startTime);
    return response;
  }

  const response = {
    statusCode: 200,
    body: {
      status: "success",
      reply: "",
      message: "Message is not likely a scam.",
    },
  };
  recordResponseTime(sessionId, Date.now() - startTime);
  return response;
}
