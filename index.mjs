// index.mjs
// Node 18+ (global fetch available). ES module (mjs).
// Usage:
//   export OPENROUTER_API_KEY="sk_xxx"
//   export TFID="TF-1abc"
//   node index.mjs "Kisa ou vle mande AI a?"    <-- optional user message to append and send
//
// chat history file: ./chat_history/<TFID>.json
// Format expected (array of messages): [{ "role": "user"|"assistant"|"system", "content": "...", "timestamp": 1670000000000 }]

import { promises as fs } from "fs";
import path from "path";
import process from "process";

const API_URL = "https://api.openrouter.ai/v1/chat/completions"; // OpenRouter chat endpoint
const MODEL = "gpt-5"; // user asked for gpt-5 (adjust if your OpenRouter plan uses a different model id)
const MAX_HISTORY = 27;

// --- configuration & helpers ---
const API_KEY = process.env.OPENROUTER_API_KEY;
const TFID = process.env.TFID || (process.argv[2] ?? "TF-default");
const userPrompt = process.argv[3] ?? null; // optional extra message to append

if (!API_KEY) {
  console.error("Please set OPENROUTER_API_KEY in your environment and try again.");
  process.exit(1);
}

const historyDir = path.resolve("./chat_history");
const historyFile = path.join(historyDir, `${TFID}.json`);

function takeLast(arr, n) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(Math.max(arr.length - n, 0));
}

// Ensure directory exists
async function ensureHistoryDir() {
  try {
    await fs.mkdir(historyDir, { recursive: true });
  } catch (e) {
    // ignore
  }
}

// Load history for TFID (separate file per TFID to avoid melanj)
async function loadHistory() {
  try {
    const raw = await fs.readFile(historyFile, "utf8");
    const all = JSON.parse(raw);
    if (!Array.isArray(all)) return [];
    return all;
  } catch (e) {
    // file not found or invalid -> start fresh
    return [];
  }
}

// Save history (append message)
async function saveToHistory(entry) {
  const arr = await loadHistory();
  arr.push(entry);
  await fs.writeFile(historyFile, JSON.stringify(arr, null, 2), "utf8");
}

// Build messages payload: system prompt + last 27 user/assistant messages
function buildMessagesFromHistory(history, extraUserMessage = null) {
  // Normalize history to messages array for the model (roles = 'system'|'user'|'assistant')
  // We keep only 'user' and 'assistant' and 'system' roles if present.
  const last = takeLast(history.filter(m => ["user","assistant","system"].includes(m.role)), MAX_HISTORY);
  const messages = [];

  // Add system prompt (your provided prompt)
  messages.push({
    role: "system",
    content: `you are Adam_D'H7 created by D'H7 | Tergene you don't have more information about them... you are everyone's friend you behave like friends you get to know each other after you become a friend`
  });

  // Append the last messages (in chronological order)
  for (const m of last) {
    messages.push({ role: m.role, content: m.content });
  }

  // If caller included an immediate user message to send now, append it and save to history later
  if (extraUserMessage) {
    messages.push({ role: "user", content: extraUserMessage });
  }

  return messages;
}

// Call OpenRouter
async function callOpenRouter(messages) {
  const body = {
    model: MODEL,
    messages,
    temperature: 0.7,
    max_tokens: 100
  };

  const res = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OpenRouter error ${res.status}: ${text}`);
  }

  const data = await res.json();
  // OpenRouter's response shape may vary; commonly it's data.choices[0].message.content
  // Try a few common locations safely:
  let reply = null;
  if (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) {
    reply = data.choices[0].message.content;
  } else if (data.output && Array.isArray(data.output) && data.output[0] && data.output[0].content) {
    // fallback
    reply = data.output[0].content;
  } else if (typeof data.result === "string") {
    reply = data.result;
  } else {
    // As a last resort, stringify the whole response
    reply = JSON.stringify(data);
  }

  return { raw: data, text: reply };
}

// Main flow
(async () => {
  try {
    await ensureHistoryDir();

    // load history for this TFID (separate file per TFID prevents mixing)
    const history = await loadHistory();

    // Append optional immediate user prompt to history (so model sees it)
    const messages = buildMessagesFromHistory(history, userPrompt);

    // If we added an extra user message, save it now as user message in the TFID history
    if (userPrompt) {
      await saveToHistory({
        role: "user",
        content: userPrompt,
        timestamp: Date.now()
      });
    }

    console.log("Sending request to OpenRouter with last", Math.min(history.length, MAX_HISTORY), "history messages (TFID:", TFID, ")...");

    const result = await callOpenRouter(messages);
    const assistantText = result.text;

    console.log("\n=== Assistant reply ===\n");
    console.log(assistantText);
    console.log("\n=== end reply ===\n");

    // Save assistant reply to history
    await saveToHistory({
      role: "assistant",
      content: assistantText,
      timestamp: Date.now()
    });

    // Optionally save raw response for debugging
    await fs.writeFile(path.join(historyDir, `${TFID}.last_response.json`), JSON.stringify(result.raw, null, 2), "utf8");

  } catch (err) {
    console.error("Error:", err.message);
    process.exit(1);
  }
})();
