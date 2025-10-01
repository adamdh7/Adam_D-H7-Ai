
import dotenv from "dotenv";
dotenv.config(); // <-- chaje .env an premye

import { promises as fs } from "fs";
import path from "path";
import process from "process";

const API_URL = "https://api.openrouter.ai/v1/chat/completions";
const MODEL = "gpt-5";
const MAX_HISTORY = 27;

// --- configuration & helpers ---
const API_KEY = process.env.OPENROUTER_API_KEY;
const TFID = process.env.TFID || (process.argv[2] ?? "TF-default");
const userPrompt = process.argv[2] && !process.env.TFID && process.argv[3] ? process.argv[3] : (process.argv[2] && process.env.TFID ? process.argv[2] : process.argv[3] ?? null);
// Explanation: allow multiple ways to pass args/env:
//  - If TFID in .env, run node index.mjs "message"
//  - Or run TFID=TF-1abc node index.mjs "message"
//  - Or run node index.mjs TF-1abc "message"

if (!API_KEY) {
  console.error("Error: OPENROUTER_API_KEY pa jwenn. Mete li nan .env oswa kòm variable anviwònman.");
  process.exit(1);
}

const historyDir = path.resolve("./chat_history");
const historyFile = path.join(historyDir, `${TFID}.json`);

function takeLast(arr, n) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(Math.max(arr.length - n, 0));
}

async function ensureHistoryDir() {
  try { await fs.mkdir(historyDir, { recursive: true }); } catch (e) { /* ignore */ }
}

async function loadHistory() {
  try {
    const raw = await fs.readFile(historyFile, "utf8");
    const all = JSON.parse(raw);
    if (!Array.isArray(all)) return [];
    return all;
  } catch (e) {
    return [];
  }
}

async function saveToHistory(entry) {
  const arr = await loadHistory();
  arr.push(entry);
  await fs.writeFile(historyFile, JSON.stringify(arr, null, 2), "utf8");
}

function buildMessagesFromHistory(history, extraUserMessage = null) {
  const last = takeLast(history.filter(m => ["user","assistant","system"].includes(m.role)), MAX_HISTORY);
  const messages = [];

  messages.push({
    role: "system",
    content: `you are Adam_D'H7 created by D'H7 | Tergene you don't have more information about them... you are everyone's friend you behave like friends you get to know each other after you become a friend`
  });

  for (const m of last) {
    messages.push({ role: m.role, content: m.content });
  }

  if (extraUserMessage) {
    messages.push({ role: "user", content: extraUserMessage });
  }

  return messages;
}

async function callOpenRouter(messages) {
  const body = {
    model: MODEL,
    messages,
    temperature: 0.7,
    max_tokens: 800
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

  let reply = null;
  if (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) {
    reply = data.choices[0].message.content;
  } else if (data.output && Array.isArray(data.output) && data.output[0] && data.output[0].content) {
    reply = data.output[0].content;
  } else if (typeof data.result === "string") {
    reply = data.result;
  } else {
    reply = JSON.stringify(data);
  }

  return { raw: data, text: reply };
}

// Main flow
(async () => {
  try {
    await ensureHistoryDir();

    const history = await loadHistory();

    // Si userPrompt egziste kòm arg, li ka deja te sove anba kèk kondisyon.
    // Nou itilize buildMessages pou mete system + dènye 27 mesaj.
    const messages = buildMessagesFromHistory(history, userPrompt);

    // Si nou gen yon mesaj nouvo itilizatè, sove li anvan rele API
    if (userPrompt) {
      await saveToHistory({
        role: "user",
        content: userPrompt,
        timestamp: Date.now()
      });
    }

    console.log("Voye demann ak dènye", Math.min(history.length, MAX_HISTORY), "mesaj (TFID:", TFID, ")...");

    const result = await callOpenRouter(messages);
    const assistantText = result.text;

    console.log("\n=== Assistant reply ===\n");
    console.log(assistantText);
    console.log("\n=== end reply ===\n");

    await saveToHistory({
      role: "assistant",
      content: assistantText,
      timestamp: Date.now()
    });

    // Save raw response for debug
    await fs.writeFile(path.join(historyDir, `${TFID}.last_response.json`), JSON.stringify(result.raw, null, 2), "utf8");

  } catch (err) {
    console.error("Error:", err.message || err);
    process.exit(1);
  }
})();
