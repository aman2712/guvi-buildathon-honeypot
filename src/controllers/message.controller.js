import { processMessage } from "../services/honeypot.service.js";

export async function handleMessage(req, res) {
  try {
    const { statusCode, body } = await processMessage(req.body);
    return res.status(statusCode).json(body);
  } catch (error) {
    const status = 400;
    console.error("[Request] Unhandled error", error);
    return res
      .status(status)
      .json({ status: "failed", reply: "", message: error.message });
  }
}
