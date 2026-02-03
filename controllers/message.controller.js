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
  markExtractionRun,
  setCallbackSent,
  setConversationEnded,
  setInitialScamAssessment,
  updateDialogState,
  updateIntelligence,
  updateMetadata,
} from "../storage/conversationStore.js";
import { sendFinalResult } from "../services/callback.service.js";

const MIN_TOTAL_MESSAGES = Number(process.env.MIN_TOTAL_MESSAGES || 18);
const MIN_SCAMMER_MESSAGES = Number(process.env.MIN_SCAMMER_MESSAGES || 10);
const MIN_EXTRACTION_RUNS = Number(process.env.MIN_EXTRACTION_RUNS || 3);
const GRACE_MESSAGES = Number(process.env.GRACE_MESSAGES || 4);
const REQUIRE_PRIMARY_INTEL = process.env.REQUIRE_PRIMARY_INTEL === "true";

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

function buildDialogState(session) {
  const have = {
    phoneNumber: (session.extractedIntelligence.phoneNumbers || []).length > 0,
    upiId: (session.extractedIntelligence.upiIds || []).length > 0,
    bankAccount: (session.extractedIntelligence.bankAccounts || []).length > 0,
    phishingLink:
      (session.extractedIntelligence.phishingLinks || []).length > 0,
    caseId: (session.extractedIntelligence.caseIds || []).length > 0,
    agentName: (session.extractedIntelligence.agentNames || []).length > 0,
    claimedOrg: Boolean(session.scamSignals?.claimedOrganization),
  };

  return {
    askedCounts: session.dialogState?.askedCounts || {},
    have,
    lastIntentTags: session.dialogState?.lastIntentTags || [],
  };
}

export async function handleMessage(req, res) {
  console.log("[Request] made");
  try {
    const { message, sessionId } = req.body || {};
    if (!sessionId || typeof sessionId !== "string") {
      console.error("[Request] Missing or invalid sessionId");
      return res.status(400).json({
        status: "failed",
        reply: "",
        message: "sessionId is required",
      });
    }
    if (!message || typeof message.text !== "string" || !message.text.trim()) {
      console.error("[Request] Missing or invalid message.text");
      return res.status(400).json({
        status: "failed",
        reply: "",
        message: "message.text is required",
      });
    }

    const session = getOrCreateSession(sessionId);
    if (session.callbackSent) {
      console.error("[Session] Callback already sent, hard stop");
      return res.json({ status: "success", reply: "" });
    }

    const normalizedMessage = {
      sender: message.sender || "scammer",
      text: message.text,
      timestamp: message.timestamp || new Date().toISOString(),
    };

    updateMetadata(sessionId, req.body?.metadata);
    appendMessage(sessionId, normalizedMessage);

    let result = session.scamAssessment;
    if (!result) {
      const prompt = buildClassifierPrompt(normalizedMessage.text);
      result = await generateJson(prompt);
      setInitialScamAssessment(sessionId, result);
    }

    if (result.scamLikely) {
      let responseReply = null;
      const dialogState = buildDialogState(session);
      const agentPrompt = buildAgentReplyPrompt({
        sessionId,
        message: normalizedMessage,
        conversationHistory: session.messages,
        persona: {},
        knownIntelligence: session.extractedIntelligence,
        scamAssessment: result,
        dialogState,
      });
      const agentReply = await generateJson(
        agentPrompt,
        agentReplySchema,
        "agent_reply",
      );
      appendReply(sessionId, agentReply.reply);
      updateDialogState(sessionId, agentReply);
      responseReply = agentReply.reply;

      const updatedSession = getOrCreateSession(sessionId);
      const messagesSinceExtract =
        updatedSession.messages.length -
        updatedSession.lastExtractedMessageCount;
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

      const meetsEarlyStop = hasExtractionRun && hasAllPrimaryIntel;

      const hardStopReached = totalMessages >= MIN_TOTAL_MESSAGES + GRACE_MESSAGES;

      if (meetsEndGate || meetsEarlyStop || hardStopReached) {
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
          if (
            endSession.lastExtractedMessageCount < endSession.messages.length
          ) {
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

          if (
            endSession.scamAssessment?.scamLikely &&
            !endSession.callbackSent
          ) {
            const disengagementMessage =
              "Alright, I have what I need for now. I'll follow up shortly.";
            appendReply(sessionId, disengagementMessage);
            responseReply = disengagementMessage;

            const payloadIntel = {
              bankAccounts: endSession.extractedIntelligence.bankAccounts || [],
              upiIds: endSession.extractedIntelligence.upiIds || [],
              phishingLinks:
                endSession.extractedIntelligence.phishingLinks || [],
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
          }
        }
      }

      return res.json({
        status: "success",
        reply: responseReply || "",
      });
    }
    return res.json({ message: "Message is not likely a scam." });
  } catch (error) {
    const status = 400;
    console.error("[Request] Unhandled error", error);
    return res
      .status(status)
      .json({ status: "failed", reply: "", message: error.message });
  }
}
