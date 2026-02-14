const sessions = new Map();

export function getOrCreateSession(sessionId) {
  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, {
      sessionId,
      messages: [],
      scamAssessment: null,
      extractedIntelligence: {
        bankAccounts: [],
        upiIds: [],
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
      lastExtractedMessageCount: 0,
      extractionRuns: 0,
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
  session.messages.push({
    sender: message.sender || "scammer",
    text: message.text,
    timestamp: message.timestamp || new Date().toISOString(),
  });
  return session;
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
  return /^https?:\/\/\S+$/i.test(value.trim());
}

function isLikelyUpiId(value) {
  if (!value || typeof value !== "string") return false;
  return /^[a-z0-9._-]{2,}@[a-z0-9.-]{2,}$/i.test(value.trim());
}

export function updateIntelligence(sessionId, extractionResult) {
  const session = getOrCreateSession(sessionId);
  const intel = extractionResult?.extractedIntelligence || {};
  const sanitizedBankAccounts = filterBankAccounts(intel.bankAccounts || []);
  const rawPhishingLinks = intel.phishingLinks || [];
  const sanitizedPhishingLinks = rawPhishingLinks.filter(isLikelyPhishingLink);
  const reclassifiedUpiIds = rawPhishingLinks.filter(isLikelyUpiId);
  const mergedUpiIds = [...(intel.upiIds || []), ...reclassifiedUpiIds];

  session.extractedIntelligence = {
    bankAccounts: mergeUnique(
      session.extractedIntelligence.bankAccounts,
      sanitizedBankAccounts,
    ),
    upiIds: mergeUnique(session.extractedIntelligence.upiIds, mergedUpiIds),
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
