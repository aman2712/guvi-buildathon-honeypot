import axios from "axios";
import fs from "fs";
import path from "path";

const CALLBACK_URL =
  "https://hackathon.guvi.in/api/updateHoneyPotFinalResult";

function toLegacyPayload(payload) {
  return {
    sessionId: payload?.sessionId,
    scamDetected: Boolean(payload?.scamDetected),
    totalMessagesExchanged: Number(payload?.totalMessagesExchanged || 0),
    extractedIntelligence: {
      bankAccounts: payload?.extractedIntelligence?.bankAccounts || [],
      upiIds: payload?.extractedIntelligence?.upiIds || [],
      emailAddresses: payload?.extractedIntelligence?.emailAddresses || [],
      phishingLinks: payload?.extractedIntelligence?.phishingLinks || [],
      phoneNumbers: payload?.extractedIntelligence?.phoneNumbers || [],
      suspiciousKeywords:
        payload?.extractedIntelligence?.suspiciousKeywords || [],
    },
    agentNotes: payload?.agentNotes || "",
  };
}

function capturePayload(payload) {
  const captureFile = process.env.CALLBACK_CAPTURE_FILE;
  if (!captureFile) return;

  const capturePath = path.isAbsolute(captureFile)
    ? captureFile
    : path.join(process.cwd(), captureFile);
  const dir = path.dirname(capturePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.appendFileSync(capturePath, `${JSON.stringify(payload)}\n`);
}

async function postPayload(payload) {
  await axios.post(CALLBACK_URL, payload, {
    headers: { "Content-Type": "application/json" },
    timeout: 5000,
  });
}

export async function sendFinalResult(payload) {
  console.log("[GUVI Callback] Payload:", JSON.stringify(payload, null, 2));
  capturePayload(payload);
  const maxAttempts = 3;
  const legacyPayload = toLegacyPayload(payload);
  const hasExtendedPayload =
    Boolean(payload?.status) ||
    Boolean(payload?.engagementMetrics) ||
    Boolean(payload?.extractedIntelligence?.emailAddresses);

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await postPayload(payload);
      return;
    } catch (error) {
      const status = error.response?.status;
      const data = error.response?.data;
      console.error(
        `[GUVI Callback] Failed attempt ${attempt}/${maxAttempts}`,
      );
      if (status) console.error(`[GUVI Callback] HTTP status: ${status}`);
      if (data) console.error("[GUVI Callback] Response body:", data);

      if (
        hasExtendedPayload &&
        status &&
        status >= 400 &&
        status < 500
      ) {
        try {
          console.warn(
            "[GUVI Callback] Retrying with legacy payload format for compatibility",
          );
          await postPayload(legacyPayload);
          return;
        } catch (legacyError) {
          const legacyStatus = legacyError.response?.status;
          const legacyData = legacyError.response?.data;
          if (legacyStatus) {
            console.error(
              `[GUVI Callback] Legacy payload HTTP status: ${legacyStatus}`,
            );
          }
          if (legacyData) {
            console.error(
              "[GUVI Callback] Legacy payload response body:",
              legacyData,
            );
          }
        }
      }

      if (attempt < maxAttempts) {
        const delayMs = 300 * attempt;
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        continue;
      }

      const wrapped = new Error("GUVI callback failed");
      wrapped.status = 400;
      throw wrapped;
    }
  }
}
