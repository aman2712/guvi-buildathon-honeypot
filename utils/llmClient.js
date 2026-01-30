import axios from "axios";
import dotenv from "dotenv";
import { classificationSchema } from "../models/llmSchemas.js";

dotenv.config();

const openaiKey = process.env.OPENAI_API_KEY;
const openaiModel = process.env.OPENAI_MODEL || "gpt-4o-mini";

function extractOutputText(responseData) {
  const output = responseData?.output || [];
  for (const item of output) {
    if (item.type === "message" && Array.isArray(item.content)) {
      for (const part of item.content) {
        if (part.type === "output_text" && typeof part.text === "string") {
          return part.text.trim();
        }
      }
    }
  }
  return "";
}

export async function generateJson(
  prompt,
  schema = classificationSchema,
  schemaName = "scam_classification",
) {
  if (!openaiKey) {
    const error = new Error("OPENAI_API_KEY not configured");
    error.status = 500;
    throw error;
  }

  const response = await axios.post(
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
      timeout: 8000,
    },
  );

  const text = extractOutputText(response.data);
  if (!text) {
    const error = new Error("OpenAI returned empty response");
    error.status = 502;
    throw error;
  }

  return JSON.parse(text);
}
