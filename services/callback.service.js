import axios from "axios";

const CALLBACK_URL =
  "https://hackathon.guvi.in/api/updateHoneyPotFinalResult";

export async function sendFinalResult(payload) {
  console.log("[GUVI Callback] Payload:", JSON.stringify(payload, null, 2));
  const maxAttempts = 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await axios.post(CALLBACK_URL, payload, {
        headers: { "Content-Type": "application/json" },
        timeout: 5000,
      });
      return;
    } catch (error) {
      const status = error.response?.status;
      const data = error.response?.data;
      console.error(
        `[GUVI Callback] Failed attempt ${attempt}/${maxAttempts}`,
      );
      if (status) console.error(`[GUVI Callback] HTTP status: ${status}`);
      if (data) console.error("[GUVI Callback] Response body:", data);

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
