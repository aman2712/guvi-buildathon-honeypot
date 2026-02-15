const sessions = new Map();

function normalizeTimestamp(timestamp) {
  if (timestamp == null) return new Date().toISOString();

  if (typeof timestamp === "number" && Number.isFinite(timestamp)) {
    const asDate = new Date(timestamp);
    return Number.isNaN(asDate.getTime())
      ? new Date().toISOString()
      : asDate.toISOString();
  }

  if (typeof timestamp === "string") {
    const trimmed = timestamp.trim();
    if (!trimmed) return new Date().toISOString();

    if (/^\d{10,13}$/.test(trimmed)) {
      const numeric = Number(trimmed);
      const millis = trimmed.length === 10 ? numeric * 1000 : numeric;
      const asDate = new Date(millis);
      return Number.isNaN(asDate.getTime())
        ? new Date().toISOString()
        : asDate.toISOString();
    }

    const parsed = new Date(trimmed);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString();
    }
  }

  return new Date().toISOString();
}

function normalizeMessage(message = {}, fallbackSender = "scammer") {
  const sender =
    message?.sender === "user" || message?.sender === "scammer"
      ? message.sender
      : fallbackSender;
  const text = typeof message?.text === "string" ? message.text : "";
  const timestamp = normalizeTimestamp(message?.timestamp);

  return { sender, text, timestamp };
}

function messageKey(message = {}) {
  return `${message.sender || ""}|${message.text || ""}|${message.timestamp || ""}`;
}

export function getOrCreateSession(sessionId) {
  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, {
      sessionId,
      messages: [],
      scamAssessment: null,
      extractedIntelligence: {
        bankAccounts: [],
        upiIds: [],
        emailAddresses: [],
        phishingLinks: [],
        phoneNumbers: [],
        suspiciousKeywords: [],
        caseIds: [],
        staffIds: [],
        agentNames: [],
      },
      scamSignals: {
        claimedOrganization: null,
        claimedDepartment: null,
        scamType: "unknown",
        tactics: [],
      },
      agentNotes: "",
      metadata: {},
      startedAtMs: Date.now(),
      lastExtractedMessageCount: 0,
      extractionRuns: 0,
      primaryCaptureTotalMessages: null,
      primaryCaptureScammerMessages: null,
      lastIntelFingerprint: "",
      lastIntelGrowthScammerMessages: 0,
      endConversation: false,
      callbackSent: false,
      dialogState: {
        askedCounts: {
          link: 0,
          paymentDestination: 0,
          upiId: 0,
          bankAccount: 0,
          caseId: 0,
          agentName: 0,
          phoneNumber: 0,
          claimedOrg: 0,
        },
        lastIntentTags: [],
      },
      timing: {
        responseTimesMs: [],
      },
    });
  }
  return sessions.get(sessionId);
}

export function appendMessage(sessionId, message) {
  const session = getOrCreateSession(sessionId);
  const normalized = normalizeMessage(message, message?.sender || "scammer");
  session.messages.push(normalized);
  return session;
}

export function appendMessageIfMissing(sessionId, message) {
  const session = getOrCreateSession(sessionId);
  const normalized = normalizeMessage(message, message?.sender || "scammer");
  if (!normalized.text.trim()) {
    return { session, appended: false };
  }

  const key = messageKey(normalized);
  const alreadyExists = session.messages.some((item) => messageKey(item) === key);
  if (!alreadyExists) {
    session.messages.push(normalized);
  }
  return { session, appended: !alreadyExists };
}

export function reconcileSessionMessages(sessionId, conversationHistory = []) {
  const session = getOrCreateSession(sessionId);
  if (!Array.isArray(conversationHistory)) {
    return { session, changed: false };
  }

  const normalizedHistory = [];
  const seen = new Set();
  for (const item of conversationHistory) {
    const normalized = normalizeMessage(item, item?.sender || "scammer");
    if (!normalized.text.trim()) continue;
    const key = messageKey(normalized);
    if (seen.has(key)) continue;
    seen.add(key);
    normalizedHistory.push(normalized);
  }

  const existing = session.messages || [];
  let changed = existing.length !== normalizedHistory.length;
  if (!changed) {
    for (let index = 0; index < existing.length; index += 1) {
      if (messageKey(existing[index]) !== messageKey(normalizedHistory[index])) {
        changed = true;
        break;
      }
    }
  }

  if (changed) {
    session.messages = normalizedHistory;
    session.lastExtractedMessageCount = Math.min(
      session.lastExtractedMessageCount || 0,
      session.messages.length,
    );
  }

  return { session, changed };
}

export function appendReply(sessionId, replyText) {
  const session = getOrCreateSession(sessionId);
  session.messages.push({
    sender: "user",
    text: replyText,
    timestamp: new Date().toISOString(),
  });
  return session;
}

export function setInitialScamAssessment(sessionId, assessment) {
  const session = getOrCreateSession(sessionId);
  if (!session.scamAssessment) {
    session.scamAssessment = assessment;
  }
  return session;
}

export function updateMetadata(sessionId, metadata) {
  const session = getOrCreateSession(sessionId);
  if (metadata && typeof metadata === "object") {
    session.metadata = { ...session.metadata, ...metadata };
  }
  return session;
}

function mergeUnique(target = [], incoming = []) {
  const set = new Set(target);
  for (const item of incoming || []) {
    if (item && !set.has(item)) {
      set.add(item);
    }
  }
  return Array.from(set);
}

function normalizeLink(value) {
  if (!value || typeof value !== "string") return "";
  let normalized = value.trim();
  normalized = normalized.replace(/^[<([{"']+/, "");
  normalized = normalized.replace(/[>)]}"]+$/, "");
  normalized = normalized.replace(/[.,;:!?]+$/, "");
  return normalized.trim();
}

function isLikelyBankAccount(value) {
  if (!value || typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed) return false;

  // Reject obvious descriptive phrases.
  if (/[a-wyzA-WYZ]/.test(trimmed)) {
    return false;
  }

  // Allow digits plus common mask/separator characters.
  if (!/^[0-9Xx*\s\-_/]+$/.test(trimmed)) {
    return false;
  }

  const digitCount = (trimmed.match(/\d/g) || []).length;
  const maskCount = (trimmed.match(/[Xx*]/g) || []).length;

  // Accept if numeric length looks like an account, or heavily masked.
  return (digitCount >= 9 && digitCount <= 18) || maskCount >= 4;
}

function filterBankAccounts(list = []) {
  return list.filter((item) => isLikelyBankAccount(item));
}

function isLikelyPhishingLink(value) {
  if (!value || typeof value !== "string") return false;
  const normalized = normalizeLink(value);
  if (!normalized) return false;
  return /^https?:\/\/\S+$/i.test(normalized);
}

function normalizeHandle(value) {
  if (!value || typeof value !== "string") return "";
  return value.trim().replace(/[.,;:!?]+$/, "");
}

function hasEmailTld(domain = "") {
  return /\.[a-z]{2,}$/i.test(domain);
}

function hasUpiDomainHint(domain = "") {
  return /(upi|pay|ok|ybl|ibl|axl|oksbi|okhdfc|okicici|okaxis|okbizaxis|apl)/i.test(
    domain,
  );
}

function classifyHandle(value) {
  const normalized = normalizeHandle(value);
  if (!/^[a-z0-9._%+-]{2,}@[a-z0-9.-]{2,}$/i.test(normalized)) {
    return "unknown";
  }

  const domain = (normalized.split("@")[1] || "").toLowerCase();
  if (!domain) return "unknown";
  if (!hasEmailTld(domain)) return "upi";
  if (hasUpiDomainHint(domain)) return "upi";
  return "email";
}

function isLikelyUpiId(value) {
  return classifyHandle(value) === "upi";
}

function isLikelyEmailAddress(value) {
  return classifyHandle(value) === "email";
}

function sanitizePhishingLinks(list = []) {
  return list.map((item) => normalizeLink(item)).filter(isLikelyPhishingLink);
}

function sanitizeUpiIds(list = []) {
  return list
    .map((item) => normalizeHandle(item))
    .filter(isLikelyUpiId);
}

function sanitizeEmailAddresses(list = []) {
  return list
    .map((item) => normalizeHandle(item))
    .filter(isLikelyEmailAddress);
}

function splitHandlesByType(list = []) {
  const upiIds = [];
  const emailAddresses = [];

  for (const item of list || []) {
    const normalized = normalizeHandle(item);
    if (!normalized) continue;
    const handleType = classifyHandle(normalized);
    if (handleType === "upi") upiIds.push(normalized);
    if (handleType === "email") emailAddresses.push(normalized);
  }

  return {
    upiIds: sanitizeUpiIds(upiIds),
    emailAddresses: sanitizeEmailAddresses(emailAddresses),
  };
}

export function updateIntelligence(sessionId, extractionResult) {
  const session = getOrCreateSession(sessionId);
  const intel = extractionResult?.extractedIntelligence || {};
  const sanitizedBankAccounts = filterBankAccounts(intel.bankAccounts || []);
  const rawPhishingLinks = intel.phishingLinks || [];
  const sanitizedPhishingLinks = sanitizePhishingLinks(rawPhishingLinks);
  const handlesFromPhishingLinks = splitHandlesByType(rawPhishingLinks);
  const handlesFromUpiIds = splitHandlesByType(intel.upiIds || []);
  const handlesFromEmails = splitHandlesByType(intel.emailAddresses || []);
  const mergedUpiIds = [
    ...handlesFromUpiIds.upiIds,
    ...handlesFromEmails.upiIds,
    ...handlesFromPhishingLinks.upiIds,
  ];
  const mergedEmailAddresses = [
    ...handlesFromEmails.emailAddresses,
    ...handlesFromUpiIds.emailAddresses,
    ...handlesFromPhishingLinks.emailAddresses,
  ];

  session.extractedIntelligence = {
    bankAccounts: mergeUnique(
      session.extractedIntelligence.bankAccounts,
      sanitizedBankAccounts,
    ),
    upiIds: mergeUnique(session.extractedIntelligence.upiIds, mergedUpiIds),
    emailAddresses: mergeUnique(
      session.extractedIntelligence.emailAddresses,
      mergedEmailAddresses,
    ),
    phishingLinks: mergeUnique(
      session.extractedIntelligence.phishingLinks,
      sanitizedPhishingLinks,
    ),
    phoneNumbers: mergeUnique(
      session.extractedIntelligence.phoneNumbers,
      intel.phoneNumbers,
    ),
    suspiciousKeywords: mergeUnique(
      session.extractedIntelligence.suspiciousKeywords,
      intel.suspiciousKeywords,
    ),
    caseIds: mergeUnique(session.extractedIntelligence.caseIds, intel.caseIds),
    staffIds: mergeUnique(session.extractedIntelligence.staffIds, intel.staffIds),
    agentNames: mergeUnique(
      session.extractedIntelligence.agentNames,
      intel.agentNames,
    ),
  };

  if (extractionResult?.scamSignals) {
    const signals = extractionResult.scamSignals;
    if (signals.claimedOrganization) {
      session.scamSignals.claimedOrganization = signals.claimedOrganization;
    }
    if (signals.claimedDepartment) {
      session.scamSignals.claimedDepartment = signals.claimedDepartment;
    }
    if (signals.scamType) {
      session.scamSignals.scamType = signals.scamType;
    }
    if (Array.isArray(signals.tactics) && signals.tactics.length > 0) {
      session.scamSignals.tactics = mergeUnique(
        session.scamSignals.tactics,
        signals.tactics,
      );
    }
  }

  if (typeof extractionResult?.agentNotes === "string") {
    session.agentNotes = extractionResult.agentNotes;
  }

  return session;
}

export function markExtractionRun(sessionId) {
  const session = getOrCreateSession(sessionId);
  session.lastExtractedMessageCount = session.messages.length;
  session.extractionRuns = (session.extractionRuns || 0) + 1;
  return session;
}

export function setConversationEnded(sessionId, ended) {
  const session = getOrCreateSession(sessionId);
  session.endConversation = Boolean(ended);
  return session;
}

export function setCallbackSent(sessionId, sent) {
  const session = getOrCreateSession(sessionId);
  session.callbackSent = Boolean(sent);
  return session;
}

export function recordResponseTime(sessionId, durationMs) {
  const session = getOrCreateSession(sessionId);
  const value = Number(durationMs);
  if (!Number.isNaN(value)) {
    session.timing.responseTimesMs.push(value);
  }
  return session;
}

export function getTimingStats(sessionId) {
  const session = getOrCreateSession(sessionId);
  const times = session.timing.responseTimesMs || [];
  if (times.length === 0) {
    return { times: [], averageMs: 0 };
  }
  const total = times.reduce((sum, t) => sum + t, 0);
  return { times, averageMs: total / times.length };
}

export function updateDialogState(sessionId, agentReply) {
  const session = getOrCreateSession(sessionId);
  const askedCounts = session.dialogState?.askedCounts || {};
  const extractionTargets = agentReply?.extractionTargets || [];

  if (extractionTargets.includes("phishingLink")) {
    askedCounts.link = (askedCounts.link || 0) + 1;
  }
  if (
    extractionTargets.includes("upiId") ||
    extractionTargets.includes("bankAccount")
  ) {
    askedCounts.paymentDestination = (askedCounts.paymentDestination || 0) + 1;
  }
  if (extractionTargets.includes("upiId")) {
    askedCounts.upiId = (askedCounts.upiId || 0) + 1;
  }
  if (extractionTargets.includes("bankAccount")) {
    askedCounts.bankAccount = (askedCounts.bankAccount || 0) + 1;
  }
  if (extractionTargets.includes("caseId")) {
    askedCounts.caseId = (askedCounts.caseId || 0) + 1;
  }
  if (extractionTargets.includes("agentName")) {
    askedCounts.agentName = (askedCounts.agentName || 0) + 1;
  }
  if (extractionTargets.includes("phoneNumber")) {
    askedCounts.phoneNumber = (askedCounts.phoneNumber || 0) + 1;
  }
  if (extractionTargets.includes("claimedOrg")) {
    askedCounts.claimedOrg = (askedCounts.claimedOrg || 0) + 1;
  }

  const intentTag = agentReply?.intentTag;
  const lastIntentTags = session.dialogState?.lastIntentTags || [];
  if (intentTag) {
    const updated = [...lastIntentTags.slice(-2), intentTag];
    session.dialogState.lastIntentTags = updated;
  }
  session.dialogState.askedCounts = askedCounts;

  return session;
}

export function getSession(sessionId) {
  return sessions.get(sessionId) || null;
}
