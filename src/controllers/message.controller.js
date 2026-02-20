import { processMessage } from "../services/honeypot.service.js";

export async function handleMessage(req, res) {
  try {
    const { statusCode, body } = await processMessage(req.body);
    return res.status(statusCode).json(body);
  } catch (error) {
    console.error("[Request] Unhandled error", error);
    const payload = req.body || {};
    const hasValidEnvelope =
      typeof payload.sessionId === "string" &&
      payload.sessionId.trim() &&
      payload.message &&
      typeof payload.message.text === "string" &&
      payload.message.text.trim();

    if (hasValidEnvelope) {
      return res.status(200).json({
        status: "success",
        reply: "I am checking this now. Can you share one official contact detail for follow-up?",
      });
    }

    return res.status(400).json({
      status: "failed",
      reply: "",
      message: error.message || "Request failed",
    });
  }
}
