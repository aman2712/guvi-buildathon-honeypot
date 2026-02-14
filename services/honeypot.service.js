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
  appendMessage,
  appendReply,
  getOrCreateSession,
  getTimingStats,
  markExtractionRun,
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

function countScammerMessages(messages = []) {
  return messages.filter((msg) => msg.sender === "scammer").length;
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
    phishingLinks: uniqueSorted(intel.phishingLinks),
    phoneNumbers: uniqueSorted(intel.phoneNumbers),
    caseIds: uniqueSorted(intel.caseIds),
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

function extractInlineIntel(text = "") {
  const source = typeof text === "string" ? text : "";
  const lower = source.toLowerCase();

  const upiIds = Array.from(
    new Set(source.match(/\b[a-z0-9._-]{2,}@[a-z][a-z0-9.-]{1,}\b/gi) || []),
  );

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

  return {
    bankAccounts,
    upiIds,
    phishingLinks,
    phoneNumbers,
    suspiciousKeywords,
    caseIds,
    staffIds: [],
    agentNames: [],
  };
}

function hasInlineIntel(intel = {}) {
  return (
    (intel.bankAccounts || []).length > 0 ||
    (intel.upiIds || []).length > 0 ||
    (intel.phishingLinks || []).length > 0 ||
    (intel.phoneNumbers || []).length > 0 ||
    (intel.suspiciousKeywords || []).length > 0 ||
    (intel.caseIds || []).length > 0
  );
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

function deriveHaveFromMessages(messages = []) {
  const scammerText = (messages || [])
    .filter((msg) => msg.sender === "scammer")
    .map((msg) => msg.text || "")
    .join("\n");
  const normalized = String(scammerText || "");

  return {
    phoneNumber: /(?:\+?\d[\d\s-]{8,}\d)/.test(normalized),
    upiId: /\b[a-z0-9._-]{2,}@[a-z][a-z0-9.-]{1,}\b/i.test(normalized),
    bankAccount:
      /\b(?:account|acct|a\/c|bank)\b[\s\S]{0,24}\b\d{9,18}\b/i.test(
        normalized,
      ),
    phishingLink: /https?:\/\/\S+/i.test(normalized),
    caseId: extractCaseIdsFromText(normalized).length > 0,
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
    phishingLink:
      (session.extractedIntelligence.phishingLinks || []).length > 0,
    caseId: (session.extractedIntelligence.caseIds || []).length > 0,
    agentName: (session.extractedIntelligence.agentNames || []).length > 0,
    claimedOrg: Boolean(session.scamSignals?.claimedOrganization),
  };
  const observedHave = deriveHaveFromMessages(session.messages || []);
  const have = {
    phoneNumber: baseHave.phoneNumber || observedHave.phoneNumber,
    upiId: baseHave.upiId || observedHave.upiId,
    bankAccount: baseHave.bankAccount || observedHave.bankAccount,
    phishingLink: baseHave.phishingLink || observedHave.phishingLink,
    caseId: baseHave.caseId || observedHave.caseId,
    agentName: baseHave.agentName || observedHave.agentName,
    claimedOrg: baseHave.claimedOrg || observedHave.claimedOrg,
  };

  return {
    askedCounts: session.dialogState?.askedCounts || {},
    have,
    lastIntentTags: session.dialogState?.lastIntentTags || [],
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
  const canAsk = (key) => (asked[key] || 0) < 2;

  // Priority is explicit and deterministic to avoid loops.
  if (!have.upiId && canAsk("upiId")) return "upiId";
  if (!have.bankAccount && canAsk("bankAccount")) return "bankAccount";
  if (!have.phishingLink && canAsk("link")) return "phishingLink";
  if (!have.phoneNumber && canAsk("phoneNumber")) return "phoneNumber";
  if (!have.agentName && canAsk("agentName")) return "agentName";
  if (!have.caseId && canAsk("caseId")) return "caseId";
  if (!have.claimedOrg && canAsk("claimedOrg")) return "claimedOrg";
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
  if (/\bcase\s*id\b|\breference\b/i.test(lower)) targets.add("caseId");
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
  if (target === "caseId") return "caseId";
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
  if (target === "agentName") return /\bname\b/.test(text);
  if (target === "caseId") return /\bcase\b|\breference\b/.test(text);
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
  if (target === "agentName") {
    return "Who should I ask for when I follow up on this?";
  }
  if (target === "caseId") {
    return "Which case ID should I quote so this request is tracked?";
  }
  if (target === "claimedOrg") {
    return "Which official organization name should I mention for this verification?";
  }
  return "";
}

function nonRepeatingFallbackReply(session) {
  const variants = [
    "Thanks, I noted that. Is there any other official detail I should keep for verification?",
    "Noted. If there is any additional reference or contact detail, share it now.",
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

export async function processMessage(payload) {
  console.log("[Request] made");
  const startTime = Date.now();
  const { message, sessionId, metadata } = payload || {};

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
    const response = { statusCode: 200, body: { status: "success", reply: "" } };
    recordResponseTime(sessionId, Date.now() - startTime);
    return response;
  }

  const normalizedMessage = {
    sender: message.sender || "scammer",
    text: message.text,
    timestamp: message.timestamp || new Date().toISOString(),
  };

  updateMetadata(sessionId, metadata);
  appendMessage(sessionId, normalizedMessage);

  let result = session.scamAssessment;
  if (!result) {
    const prompt = buildClassifierPrompt(normalizedMessage.text);
    result = await generateJson(prompt);
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
    const agentReply = await generateJson(
      agentPrompt,
      agentReplySchema,
      "agent_reply",
    );

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
      const extraction = await generateJson(
        extractPrompt,
        intelligenceExtractionSchema,
        "intelligence_extraction",
      );
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
      intelStalled;

    const hardStopReached =
      totalMessages >= MIN_TOTAL_MESSAGES + GRACE_MESSAGES;
    const exhaustedDialogReady =
      exhaustedDialogFallback &&
      hasExtractionRun &&
      hasAllPrimaryIntel &&
      hasAskedOrCapturedLink &&
      totalMessages >= Math.max(12, MIN_TOTAL_MESSAGES - 2) &&
      scammerMessages >= Math.max(6, MIN_SCAMMER_MESSAGES - 2);

    const shouldEvaluateEnd =
      hardStopReached ||
      meetsEarlyStop ||
      exhaustedDialogReady ||
      (meetsEndGate && hasAskedOrCapturedLink && intelStalled);

    if (shouldEvaluateEnd) {
      const endPrompt = buildConversationEndPrompt({
        sessionId,
        conversation: updatedSession.messages,
        scamAssessment: updatedSession.scamAssessment,
        extractedIntelligence: updatedSession.extractedIntelligence,
      });
      const endDecision = hardStopReached
        ? { endConversation: true, reason: "Hard stop reached" }
        : await generateJson(
            endPrompt,
            conversationEndSchema,
            "conversation_end",
          );

      if (endDecision.endConversation) {
        setConversationEnded(sessionId, true);
        const endSession = getOrCreateSession(sessionId);
        if (endSession.lastExtractedMessageCount < endSession.messages.length) {
          const finalExtractPrompt = buildIntelligenceExtractionPrompt({
            sessionId,
            conversation: endSession.messages,
            metadata: endSession.metadata,
          });
          const finalExtraction = await generateJson(
            finalExtractPrompt,
            intelligenceExtractionSchema,
            "intelligence_extraction_final",
          );
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
            phishingLinks: endSession.extractedIntelligence.phishingLinks || [],
            phoneNumbers: endSession.extractedIntelligence.phoneNumbers || [],
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

          const payload = {
            sessionId,
            scamDetected: true,
            totalMessagesExchanged: endSession.messages.length,
            extractedIntelligence: payloadIntel,
            agentNotes: noteParts.join(" "),
          };
            await sendFinalResult(payload);
            setCallbackSent(sessionId, true);
            setConversationEnded(sessionId, true);

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
    body: { message: "Message is not likely a scam." },
  };
  recordResponseTime(sessionId, Date.now() - startTime);
  return response;
}
