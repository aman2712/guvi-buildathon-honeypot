import axios from "axios";

const CALLBACK_URL =
  "https://hackathon.guvi.in/api/updateHoneyPotFinalResult";

export async function sendFinalResult(payload) {
  console.log("[GUVI Callback] Payload:", JSON.stringify(payload, null, 2));
  await axios.post(CALLBACK_URL, payload, {
    headers: { "Content-Type": "application/json" },
    timeout: 5000,
  });
}
