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
      },
      scamSignals: {
        claimedOrganization: null,
        scamType: "unknown",
        tactics: [],
      },
      agentNotes: "",
      metadata: {},
      lastExtractedMessageCount: 0,
      endConversation: false,
      callbackSent: false,
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

export function updateIntelligence(sessionId, extractionResult) {
  const session = getOrCreateSession(sessionId);
  const intel = extractionResult?.extractedIntelligence || {};

  session.extractedIntelligence = {
    bankAccounts: mergeUnique(
      session.extractedIntelligence.bankAccounts,
      intel.bankAccounts,
    ),
    upiIds: mergeUnique(session.extractedIntelligence.upiIds, intel.upiIds),
    phishingLinks: mergeUnique(
      session.extractedIntelligence.phishingLinks,
      intel.phishingLinks,
    ),
    phoneNumbers: mergeUnique(
      session.extractedIntelligence.phoneNumbers,
      intel.phoneNumbers,
    ),
    suspiciousKeywords: mergeUnique(
      session.extractedIntelligence.suspiciousKeywords,
      intel.suspiciousKeywords,
    ),
  };

  if (extractionResult?.scamSignals) {
    const signals = extractionResult.scamSignals;
    if (signals.claimedOrganization) {
      session.scamSignals.claimedOrganization = signals.claimedOrganization;
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

export function getSession(sessionId) {
  return sessions.get(sessionId) || null;
}
