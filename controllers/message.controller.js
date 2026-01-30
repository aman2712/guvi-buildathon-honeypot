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
  updateIntelligence,
  updateMetadata,
} from "../storage/conversationStore.js";
import { sendFinalResult } from "../services/callback.service.js";

const MIN_TOTAL_MESSAGES = Number(process.env.MIN_TOTAL_MESSAGES || 10);
const MIN_SCAMMER_MESSAGES = Number(process.env.MIN_SCAMMER_MESSAGES || 5);
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

export async function handleMessage(req, res) {
  try {
    console.log("request was made!");
    const { message, sessionId } = req.body || {};
    if (!sessionId || typeof sessionId !== "string") {
      return res.status(400).json({
        status: "error",
        message: "sessionId is required",
      });
    }
    if (!message || typeof message.text !== "string" || !message.text.trim()) {
      return res.status(400).json({
        status: "error",
        message: "message.text is required",
      });
    }

    const normalizedMessage = {
      sender: message.sender || "scammer",
      text: message.text,
      timestamp: message.timestamp || new Date().toISOString(),
    };

    const session = getOrCreateSession(sessionId);
    updateMetadata(sessionId, req.body?.metadata);
    appendMessage(sessionId, normalizedMessage);

    let result = session.scamAssessment;
    if (!result) {
      const prompt = buildClassifierPrompt(normalizedMessage.text);
      result = await generateJson(prompt);
      setInitialScamAssessment(sessionId, result);
    }

    if (result.scamLikely) {
      const agentPrompt = buildAgentReplyPrompt({
        sessionId,
        message: normalizedMessage,
        conversationHistory: session.messages,
        persona: {},
        knownIntelligence: session.extractedIntelligence,
        scamAssessment: result,
      });
      const agentReply = await generateJson(
        agentPrompt,
        agentReplySchema,
        "agent_reply",
      );
      appendReply(sessionId, agentReply.reply);

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
      const hasPrimaryIntelItem = hasPrimaryIntel(
        updatedSession.extractedIntelligence,
      );
      const meetsEndGate =
        totalMessages >= MIN_TOTAL_MESSAGES &&
        scammerMessages >= MIN_SCAMMER_MESSAGES &&
        hasExtractionRun &&
        (!REQUIRE_PRIMARY_INTEL || hasPrimaryIntelItem);

      if (meetsEndGate) {
        const endPrompt = buildConversationEndPrompt({
          sessionId,
          conversation: updatedSession.messages,
          scamAssessment: updatedSession.scamAssessment,
          extractedIntelligence: updatedSession.extractedIntelligence,
        });
        const endDecision = await generateJson(
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
            const payload = {
              sessionId,
              scamDetected: true,
              totalMessagesExchanged: endSession.messages.length,
              extractedIntelligence: endSession.extractedIntelligence,
              agentNotes: endSession.agentNotes || "",
            };
            await sendFinalResult(payload);
            setCallbackSent(sessionId, true);
          }
        }
      }

      return res.json({
        status: "success",
        reply: agentReply.reply,
      });
    }
    return res.json({ message: "Message is not likely a scam." });
  } catch (error) {
    const status = error.status || 500;
    return res.status(status).json({ status: "error", message: error.message });
  }
}
