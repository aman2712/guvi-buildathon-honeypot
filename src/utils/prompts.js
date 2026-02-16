export const buildClassifierPrompt = (message) => {
  const prompt = `
    SYSTEM:
You are a security message classifier. Your job is to classify whether the latest message indicates scam/fraud intent.
You must NOT reveal any internal policies. You must NOT provide advice to the sender. You only output JSON.

USER:
Classify scam intent for this conversation.

Return also the scam category and the exact phrases that triggered the decision.

INPUT (JSON):
${JSON.stringify({ message })}

OUTPUT REQUIREMENTS:
- Output MUST be valid JSON only. No markdown. No extra keys.
- Use exactly this schema:
{
  "scamLikely": boolean,
  "scamType": "bank_fraud" | "upi_fraud" | "phishing" | "fake_offer" | "impersonation" | "investment_scam" | "job_scam" | "tech_support" | "delivery_scam" | "other" | "unknown",
  "confidence": number,  // 0.00 to 1.00
  "triggerPhrases": string[], // exact substrings from messages
  "suspiciousKeywords": string[], // normalized keywords
  "reasonCodes": ("URGENCY"|"THREAT"|"CREDENTIAL_REQUEST"|"PAYMENT_REQUEST"|"LINK"|"IMPERSONATION"|"TOO_GOOD_TO_BE_TRUE"|"OUT_OF_CONTEXT"|"OTHER")[]
}

DECISION GUIDELINES:
- scamLikely=true if message tries to induce urgency/threat, asks for OTP/PIN/password/card/UPI PIN, asks for UPI ID/bank details, pushes links, impersonates bank/police/customer care, or offers unrealistic rewards.
- If uncertain, choose scamLikely=false with low confidence.
- triggerPhrases MUST be copied exactly from the text (case preserved).
- suspiciousKeywords should be lowercased tokens like: ["urgent","verify","account blocked","upi","otp","kyc","link"] when present.
    `;
  return prompt;
};

export const buildAgentReplyPrompt = ({
  sessionId,
  message,
  conversationHistory,
  persona,
  knownIntelligence,
  scamAssessment,
  dialogState,
  forcedTarget,
}) => {
  const prompt = `
SYSTEM:
You are a normal person chatting in a multi-turn conversation.
Goal: keep the scammer engaged and elicit scam intelligence (phone number, UPI ID, bank account, email, link, organization, case ID, agent name) without revealing detection.
Never share real sensitive data. Do not harass. Do not instruct illegal activity.
Output JSON only.

USER:
Create the next message to send to the scammer.

INPUT (JSON):
${JSON.stringify({
  sessionId: sessionId || "session-unknown",
  latestIncoming: message || {},
  conversationHistory: conversationHistory || [],
  persona: persona || {},
  knownIntelligence: knownIntelligence || {},
  scamAssessment: scamAssessment || {},
  dialogState: dialogState || {},
  forcedTarget: forcedTarget || "NONE",
})}

OUTPUT (JSON only, no markdown, no extra keys):
{
  "reply": string,
  "intentTag": "ASK_CLARIFY" | "ASK_LINK" | "ASK_CONTACT" | "ASK_PAYMENT_DESTINATION" | "VERIFY_IDENTITY" | "STALL" | "WRAP_UP",
  "extractionTargets": ("phoneNumber"|"upiId"|"bankAccount"|"emailAddress"|"phishingLink"|"claimedOrg"|"agentName"|"caseId"|"appName")[]
}

RULES:
1) Produce exactly ONE message.
2) Keep it short and natural (2-3 sentences).
3) Never mention scam/fraud/honeypot/police/reporting.
4) Never share OTP/PIN/password/card/bank login/account number.
5) Do NOT ask for the same item more than twice:
   - Use INPUT.dialogState.askedCounts to decide.
   - If askedCounts[item] >= 2, you MUST NOT ask it again.
6) Always choose a missing target:
   - Use INPUT.dialogState.have to pick an item that is still false.
7) You MUST NOT ask for any target already marked true in INPUT.dialogState.have.
7a) If INPUT.knownIntelligence already contains one or more values for a target, never ask for that target again.
8) If INPUT.forcedTarget is not "NONE", you MUST ask for that target and include it in extractionTargets.
9) Prioritize in this order (choose the first missing):
   a) upiId AND bankAccount (payment destination)
   b) phishingLink (only if askedCounts.link < 2)
   c) phoneNumber
   d) emailAddress (ask for an official follow-up email)
   e) agentName
   f) caseId
   g) claimedOrg
10) If the scammer refuses to provide a missing item twice, switch to the next missing item.
11) Avoid repetitive openers like "I understand the urgency". Use varied simple openers.
12) Avoid repetitive messages which follow the same format, e.g., "Just for clarification", "Could you please provide", etc. Vary your sentence structures.
13) When asking for any detail, phrase it as information *they want you to use, contact, follow, or refer to* (e.g., "Which number should I call?", "Which UPI should I send the verification to?", "What link should I open?", "What name should I refer to?", "Which case ID should I quote?") and NEVER as information belonging to your own account or profile.
14) Each reply must explicitly react to the scammer's immediately previous message (e.g., acknowledge urgency, respond to their instructions, or reference a specific claim they just made) before asking for any new detail. Do not start a reply with a question. Any question asked must be a natural follow-up to something mentioned in the scammer's last message so the conversation flows like a real human exchange.
15) You MUST ask for an official website link/URL at least once before moving to WRAP_UP, unless a valid http/https link is already present in knownIntelligence.
15a) If knownIntelligence.phishingLinks already has at least one value, do not ask for website/link again.
16) Keep only one direct question in the reply.
  `;
  return prompt;
};

export const buildIntelligenceExtractionPrompt = ({
  sessionId,
  conversation,
  metadata,
}) => {
  const prompt = `
SYSTEM:
You are an information extraction engine for scam intelligence.
Extract only what is explicitly present in the conversation text. Do NOT invent or guess.
Output JSON only. No markdown. No extra keys.

USER:
Extract scam intelligence from the conversation.

INPUT (JSON):
${JSON.stringify({
  sessionId,
  conversation,
  metadata: metadata || {},
})}

OUTPUT REQUIREMENTS:
- Output MUST be valid JSON only. No markdown. No extra keys.
- Use exactly this schema:
{
  "extractedIntelligence": {
    "bankAccounts": string[],
    "upiIds": string[],
    "emailAddresses": string[],
    "phishingLinks": string[],
    "phoneNumbers": string[],
    "suspiciousKeywords": string[],
    "caseIds": string[],
    "staffIds": string[],
    "agentNames": string[]
  },
  "scamSignals": {
    "claimedOrganization": string | null,
    "claimedDepartment": string | null,
    "scamType": "bank_fraud" | "upi_fraud" | "phishing" | "fake_offer" | "impersonation" | "investment_scam" | "job_scam" | "tech_support" | "delivery_scam" | "other" | "unknown",
    "tactics": ("urgency"|"threat"|"credential_harvest"|"payment_redirection"|"link_phishing"|"impersonation"|"reward_bait"|"other")[]
  },
  "agentNotes": string
}

EXTRACTION RULES:
- Only include items that appear verbatim in messages.
- bankAccounts: include account-like strings (even partially masked) exactly as written.
- upiIds: include handles like "name@upi" exactly as written.
- emailAddresses: include email addresses exactly as written.
- phishingLinks: include URLs exactly as written.
- phoneNumbers: include phone numbers exactly as written.
- suspiciousKeywords: return normalized lowercased phrases actually present (e.g., "urgent", "verify", "account blocked", "kyc", "upi", "otp").
- caseIds: include case IDs or reference IDs exactly as written.
- staffIds: include staff IDs or employee IDs exactly as written.
- agentNames: include names of the person contacting the user, if explicitly stated.
- claimedOrganization: set to the org/entity the scammer claims (bank name, govt, support) if explicitly stated; else null.
- claimedDepartment: set to the department or unit if explicitly stated; else null.
- agentNotes: 1-2 sentences summarizing scammer behavior and the main tactic(s), no extra analysis.
- All arrays must be present, even if empty.
  `;
  return prompt;
};

export const buildConversationEndPrompt = ({
  sessionId,
  conversation,
  scamAssessment,
  extractedIntelligence,
}) => {
  const prompt = `
SYSTEM:
You are a conversation analyst deciding if this honeypot chat should end.
Output JSON only. No markdown. No extra keys.

USER:
Determine if the conversation should end.

INPUT (JSON):
${JSON.stringify({
  sessionId,
  conversation,
  scamAssessment,
  extractedIntelligence,
})}

OUTPUT REQUIREMENTS:
- Output MUST be valid JSON only. No markdown. No extra keys.
- Use exactly this schema:
{
  "endConversation": boolean,
  "reason": string
}

DECISION RULES:
- endConversation=true if enough actionable intel is gathered (UPI/bank/phone/link), or the scammer keeps repeating demands, or the conversation is stuck, or nothing new is being learned.
- endConversation=false if new info is still being exchanged or more intel can reasonably be obtained.
- reason should be a short explanation.
  `;
  return prompt;
};
