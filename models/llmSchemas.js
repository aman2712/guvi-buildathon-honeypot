export const classificationSchema = {
  type: "object",
  properties: {
    scamLikely: { type: "boolean" },
    scamType: {
      type: "string",
      enum: [
        "bank_fraud",
        "upi_fraud",
        "phishing",
        "fake_offer",
        "impersonation",
        "investment_scam",
        "job_scam",
        "tech_support",
        "delivery_scam",
        "other",
        "unknown",
      ],
    },
    confidence: { type: "number" },
    triggerPhrases: { type: "array", items: { type: "string" } },
    suspiciousKeywords: { type: "array", items: { type: "string" } },
    reasonCodes: {
      type: "array",
      items: {
        type: "string",
        enum: [
          "URGENCY",
          "THREAT",
          "CREDENTIAL_REQUEST",
          "PAYMENT_REQUEST",
          "LINK",
          "IMPERSONATION",
          "TOO_GOOD_TO_BE_TRUE",
          "OUT_OF_CONTEXT",
          "OTHER",
        ],
      },
    },
  },
  required: [
    "scamLikely",
    "scamType",
    "confidence",
    "triggerPhrases",
    "suspiciousKeywords",
    "reasonCodes",
  ],
  additionalProperties: false,
};

export const agentReplySchema = {
  type: "object",
  properties: {
    reply: { type: "string" },
    intentTag: {
      type: "string",
      enum: [
        "ASK_CLARIFY",
        "ASK_LINK",
        "ASK_CONTACT",
        "ASK_PAYMENT_DESTINATION",
        "STALL",
        "VERIFY_IDENTITY",
        "WRAP_UP",
      ],
    },
    extractionTargets: {
      type: "array",
      items: {
        type: "string",
        enum: [
          "phoneNumber",
          "upiId",
          "bankAccount",
          "phishingLink",
          "claimedOrg",
          "agentName",
          "caseId",
          "appName",
        ],
      },
    },
  },
  required: ["reply", "intentTag", "extractionTargets"],
  additionalProperties: false,
};

export const intelligenceExtractionSchema = {
  type: "object",
  properties: {
    extractedIntelligence: {
      type: "object",
      properties: {
        bankAccounts: { type: "array", items: { type: "string" } },
        upiIds: { type: "array", items: { type: "string" } },
        phishingLinks: { type: "array", items: { type: "string" } },
        phoneNumbers: { type: "array", items: { type: "string" } },
        suspiciousKeywords: { type: "array", items: { type: "string" } },
        caseIds: { type: "array", items: { type: "string" } },
        staffIds: { type: "array", items: { type: "string" } },
        agentNames: { type: "array", items: { type: "string" } },
      },
      required: [
        "bankAccounts",
        "upiIds",
        "phishingLinks",
        "phoneNumbers",
        "suspiciousKeywords",
        "caseIds",
        "staffIds",
        "agentNames",
      ],
      additionalProperties: false,
    },
    scamSignals: {
      type: "object",
      properties: {
        claimedOrganization: { type: ["string", "null"] },
        claimedDepartment: { type: ["string", "null"] },
        scamType: {
          type: "string",
          enum: [
            "bank_fraud",
            "upi_fraud",
            "phishing",
            "fake_offer",
            "impersonation",
            "investment_scam",
            "job_scam",
            "tech_support",
            "delivery_scam",
            "other",
            "unknown",
          ],
        },
        tactics: {
          type: "array",
          items: {
            type: "string",
            enum: [
              "urgency",
              "threat",
              "credential_harvest",
              "payment_redirection",
              "link_phishing",
              "impersonation",
              "reward_bait",
              "other",
            ],
          },
        },
      },
      required: ["claimedOrganization", "claimedDepartment", "scamType", "tactics"],
      additionalProperties: false,
    },
    agentNotes: { type: "string" },
  },
  required: ["extractedIntelligence", "scamSignals", "agentNotes"],
  additionalProperties: false,
};

export const conversationEndSchema = {
  type: "object",
  properties: {
    endConversation: { type: "boolean" },
    reason: { type: "string" },
  },
  required: ["endConversation", "reason"],
  additionalProperties: false,
};
