import axios from "axios";
import dotenv from "dotenv";
import { classificationSchema } from "../models/llmSchemas.js";

dotenv.config();

const openaiKey = process.env.OPENAI_API_KEY;
const openaiModel = process.env.OPENAI_MODEL || "gpt-4o-mini";
const openaiTimeoutMs = Number(process.env.OPENAI_TIMEOUT_MS || 8000);
const openaiMaxRetries = Number(process.env.OPENAI_MAX_RETRIES || 2);
const RETRYABLE_STATUS = new Set([408, 409, 429, 500, 502, 503, 504]);

function extractOutputText(responseData) {
  if (typeof responseData?.output_text === "string") {
    return responseData.output_text.trim();
  }
  const output = responseData?.output || [];
  for (const item of output) {
    if (item.type === "message" && Array.isArray(item.content)) {
      for (const part of item.content) {
        if (part.type === "output_text" && typeof part.text === "string") {
          return part.text.trim();
        }
        if (part.type === "text" && typeof part.text === "string") {
          return part.text.trim();
        }
      }
    }
  }
  return "";
}

function isRetryableNetworkCode(code = "") {
  return new Set([
    "ECONNABORTED",
    "ECONNRESET",
    "EAI_AGAIN",
    "ENOTFOUND",
    "ETIMEDOUT",
    "ERR_NETWORK",
  ]).has(code);
}

function isRetryableError(error) {
  const status = Number(error?.response?.status || 0);
  if (RETRYABLE_STATUS.has(status)) return true;
  return isRetryableNetworkCode(error?.code);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function retryDelay(attempt) {
  const base = 250 * 2 ** attempt;
  const jitter = Math.floor(Math.random() * 120);
  return base + jitter;
}

async function requestOpenAi(prompt, schema, schemaName) {
  return axios.post(
    "https://api.openai.com/v1/responses",
    {
      model: openaiModel,
      input: prompt,
      temperature: 0.1,
      text: {
        format: {
          type: "json_schema",
          name: schemaName,
          strict: true,
          schema,
        },
      },
    },
    {
      headers: {
        Authorization: `Bearer ${openaiKey}`,
        "Content-Type": "application/json",
      },
      timeout: openaiTimeoutMs,
    },
  );
}

function parseJsonSafely(text = "") {
  try {
    return JSON.parse(text);
  } catch {
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start >= 0 && end > start) {
      const candidate = text.slice(start, end + 1);
      return JSON.parse(candidate);
    }
    throw new Error("LLM returned invalid JSON");
  }
}

export async function generateJson(
  prompt,
  schema = classificationSchema,
  schemaName = "scam_classification",
) {
  if (!openaiKey) {
    const error = new Error("OPENAI_API_KEY not configured");
    error.status = 400;
    console.error("[LLM] Missing OPENAI_API_KEY");
    throw error;
  }

  let lastError = null;

  for (let attempt = 0; attempt <= openaiMaxRetries; attempt += 1) {
    let response;
    try {
      response = await requestOpenAi(prompt, schema, schemaName);
      const text = extractOutputText(response.data);
      if (!text) {
        throw new Error("OpenAI returned empty response");
      }
      return parseJsonSafely(text);
    } catch (error) {
      lastError = error;
      const shouldRetry = attempt < openaiMaxRetries && isRetryableError(error);
      if (shouldRetry) {
        const delayMs = retryDelay(attempt);
        console.warn(
          `[LLM] Retry ${attempt + 1}/${openaiMaxRetries} for schema=${schemaName} after ${delayMs}ms`,
        );
        await sleep(delayMs);
        continue;
      }
      break;
    }
  }

  const status = lastError?.response?.status;
  const data = lastError?.response?.data;
  console.error(
    `[LLM] OpenAI request failed (schema=${schemaName}, model=${openaiModel})`,
  );
  if (status) console.error(`[LLM] HTTP status: ${status}`);
  if (data) console.error("[LLM] Response body:", data);
  if (!data && lastError?.message) console.error("[LLM] Error:", lastError.message);

  const wrapped = new Error("LLM request failed");
  wrapped.status = 400;
  wrapped.details = data;
  throw wrapped;
}
