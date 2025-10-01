import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { promises as fs } from 'fs';
import crypto from 'crypto';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Config (via .env possible)
const PORT = Number(process.env.PORT) || 3000;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_ENDPOINT = process.env.OPENROUTER_ENDPOINT || 'https://openrouter.ai/api/v1/chat/completions';
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'gpt-5';

// By default keep 27 messages of chat context
const HISTORY_TAIL = Number(process.env.HISTORY_TAIL) || 27;

const DEFAULT_MAX_TOKENS = Number(process.env.DEFAULT_MAX_TOKENS) || 100;
const DEFAULT_TIMEOUT_MS = Number(process.env.DEFAULT_TIMEOUT_MS) || 30000;
const MAX_RETRIES = Number(process.env.MAX_RETRIES) || 3;
const MIN_TOKENS = Number(process.env.MIN_TOKENS) || 16;
const DEFAULT_USER_NAME = process.env.DEFAULT_USER_NAME || "Adam_D'H7";
const MAX_ALLOWED_TOKENS = Number(process.env.MAX_ALLOWED_TOKENS) || 200;
const RECOVERY_MAX_TOKENS_CAP = Number(process.env.RECOVERY_MAX_TOKENS_CAP) || 50;

// TF-7CHIF: allowed characters for ID (A..Z, a..z, 1..9)
const TF_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789';

const USERS_FILE = path.join(__dirname, 'user.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
// new file: per-user private history (by TFID)
const USER_HISTORY_FILE = path.join(__dirname, 'user_history.json');

if (!OPENROUTER_API_KEY) {
  console.error('ERROR: OPENROUTER_API_KEY missing in .env');
  process.exit(1);
}

app.use(cors({ origin: true }));
app.use(express.json({ limit: '70mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// --- file helpers ---
async function readJsonSafe(filePath, defaultValue) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      try { await fs.writeFile(filePath, JSON.stringify(defaultValue, null, 2), 'utf8'); } catch(e) {}
      return defaultValue;
    }
    throw err;
  }
}
async function writeJsonSafe(filePath, obj) {
  const tmp = filePath + '.tmp';
  const data = JSON.stringify(obj, null, 2);
  await fs.writeFile(tmp, data, 'utf8');
  await fs.rename(tmp, filePath);
}

// --- TFID generator: prefix TF- + 7 chars ---
function generateTFIDRaw(len = 7) {
  const bytes = crypto.randomBytes(len);
  let id = '';
  for (let i = 0; i < len; i++) id += TF_CHARS[bytes[i] % TF_CHARS.length];
  return id;
}
async function ensureUniqueTFID() {
  const data = await readJsonSafe(USERS_FILE, { users: [] });
  const exist = new Set((data.users || []).map(u => u.tfid));
  for (let i = 0; i < 20000; i++) {
    const candidate = 'TF-' + generateTFIDRaw(7);
    if (!exist.has(candidate)) return candidate;
  }
  return 'TF-' + crypto.randomUUID().slice(0,7).toUpperCase();
}

// initial files
await readJsonSafe(USERS_FILE, { users: [] });
await readJsonSafe(SESSIONS_FILE, { sessions: {} });
await readJsonSafe(USER_HISTORY_FILE, { histories: {} });

// --- custom system prompt (EN) ---
// Note: user requested "Text in English", "AI must always finish its sentences" and
// "AI should take its time and read the whole message before replying".
function makeSystemPrompt(tfid, sessionId, userName = null) {
  const display = userName || DEFAULT_USER_NAME || tfid;
  // Clear, English system prompt with constraints the user asked for.
  return {
    role: 'system',
    content:
`You are Adam_DH7, the personal assistant for ${display}. Session id: ${sessionId}

IMPORTANT CONSTRAINTS FOR EVERY RESPONSE:
1) Read the user's full message and the recent conversation history carefully before composing an answer.
2) Always finish your sentences. Do not stop mid-sentence or produce truncated replies.
3) Keep answers clear and concise when asked; only include reasoning when explicitly requested, and never expose internal chain-of-thought.
4) Respond in user language by default unless the user explicitly requests another language. 

You only have access to messages within this session (the last ${HISTORY_TAIL} messages) and to the private histories for the user identified by ${tfid} only if explicitly requested.`
  };
}


// --- sanitize to avoid chain-of-thought leaks ---
function looksLikeChainOfThoughtLine(line) {
  if (!line) return false;
  const s = line.toLowerCase();
  const patterns = [
    'consider', 'considering', 'i think', "i'm thinking", 'i believe',
    'je pense', 'considérant', 'réflexion', 'analyse interne',
    'thinking', 'chain of thought', 'reasoning', 'internal'
  ];
  return patterns.some(p => s.includes(p));
}
function sanitizeAssistantText(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const lines = raw.split(/\r?\n/);
  const kept = [];
  for (let ln of lines) {
    const trimmed = ln.trim();
    if (!trimmed) continue;
    if (looksLikeChainOfThoughtLine(trimmed)) continue;
    if (/^reasoning[:\s-]/i.test(trimmed)) continue;
    kept.push(trimmed);
  }
  const out = kept.join('\n').trim();
  return out === '' ? null : out;
}

// --- extraction assistant (priority message.content, then other readable fields) ---
function extractAssistantText(payloadJson) {
  if (!payloadJson) return null;
  const safe = (s) => (typeof s === 'string' && s.trim() ? s.trim() : null);

  if (Array.isArray(payloadJson.choices) && payloadJson.choices.length) {
    const c = payloadJson.choices[0];

    // 1) message.content (full) -> sanitize
    const mc = safe(c?.message?.content);
    if (mc) {
      const s = sanitizeAssistantText(mc);
      if (s) return s;
    }

    // 2) direct text
    const ct = safe(c.text);
    if (ct) {
      const s = sanitizeAssistantText(ct);
      if (s) return s;
    }

    // 3) delta content
    const d = safe(c?.delta?.content);
    if (d) {
      const s = sanitizeAssistantText(d);
      if (s) return s;
    }

    // 4) reasoning_details summary (non encrypted)
    if (Array.isArray(c?.message?.reasoning_details)) {
      for (const it of c.message.reasoning_details) {
        if (!it) continue;
        if (it.type && String(it.type).toLowerCase().includes('encrypted')) continue;
        if (typeof it.summary === 'string' && it.summary.trim()) {
          const s = it.summary.trim();
          if (!looksLikeChainOfThoughtLine(s)) {
            const ss = sanitizeAssistantText(s);
            if (ss) return ss;
          }
        }
      }
    }
    return null;
  }

  const keys = ['response','output','result','text'];
  for (const k of keys) {
    if (typeof payloadJson[k] === 'string' && payloadJson[k].trim()) {
      const s = sanitizeAssistantText(payloadJson[k]);
      if (s) return s;
    }
  }
  return null;
}

// --- fetch wrapper with timeout ---
async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const r = await fetch(url, { ...options, signal: controller.signal });
    const txt = await r.text();
    let parsed = null;
    try { parsed = JSON.parse(txt); } catch (e) {}
    return { ok: r.ok, status: r.status, text: txt, json: parsed };
  } catch (err) {
    return { ok: false, fetchError: err, status: 502, text: String(err) };
  } finally {
    clearTimeout(id);
  }
}

// --- helper: append to user_history (private per tfid) ---
async function appendUserHistory(tfid, entry) {
  const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
  hist.histories = hist.histories || {};
  hist.histories[tfid] = hist.histories[tfid] || [];
  hist.histories[tfid].push(entry);
  // optional: cap history per user to e.g. 10000 messages to avoid unbounded growth
  const CAP = 10000;
  if (hist.histories[tfid].length > CAP) {
    hist.histories[tfid] = hist.histories[tfid].slice(-CAP);
  }
  await writeJsonSafe(USER_HISTORY_FILE, hist);
}

// --- endpoints users / sessions ---
app.post('/user', async (req, res) => {
  try {
    const { name, tfid } = req.body || {};
    const data = await readJsonSafe(USERS_FILE, { users: [] });
    if (tfid) {
      const found = (data.users || []).find(u => u.tfid === tfid);
      if (found) return res.json(found);
      return res.status(404).json({ error: 'tfid_not_found' });
    }
    const newTF = await ensureUniqueTFID();
    const user = { tfid: newTF, name: name || DEFAULT_USER_NAME, createdAt: new Date().toISOString() };
    data.users = data.users || [];
    data.users.push(user);
    await writeJsonSafe(USERS_FILE, data);
    // initialize empty history for this tfid
    const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
    hist.histories = hist.histories || {};
    hist.histories[newTF] = hist.histories[newTF] || [];
    await writeJsonSafe(USER_HISTORY_FILE, hist);
    return res.json(user);
  } catch (err) {
    console.error('/user error', err);
    return res.status(500).json({ error: 'server_error', details: err.message });
  }
});
app.get('/users', async (req, res) => {
  try { const data = await readJsonSafe(USERS_FILE, { users: [] }); res.json(data.users || []); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/session', async (req, res) => {
  try {
    const { tfid } = req.body || {};
    if (!tfid) return res.status(400).json({ error: 'tfid_required' });
    const users = await readJsonSafe(USERS_FILE, { users: [] });
    const found = (users.users || []).find(u => u.tfid === tfid);
    if (!found) return res.status(404).json({ error: 'user_not_found' });
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    sessionsData.sessions = sessionsData.sessions || {};
    const sessionId = crypto.randomUUID();
    const session = { sessionId, tfid, createdAt: new Date().toISOString(), messages: [] };
    sessionsData.sessions[sessionId] = session;
    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    res.json({ sessionId, createdAt: session.createdAt });
  } catch (err) { console.error('/session error', err); res.status(500).json({ error: 'server_error', details: err.message }); }
});
app.get('/session/:id', async (req,res) => {
  try { const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} }); const s = (sessionsData.sessions || {})[req.params.id]; if (!s) return res.status(404).json({ error: 'session_not_found' }); res.json(s); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/sessions/:tfid', async (req,res) => {
  try { const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} }); const list = Object.values(sessionsData.sessions || {}).filter(s => s.tfid === req.params.tfid); res.json(list.map(s => ({ sessionId: s.sessionId, createdAt: s.createdAt }))); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// endpoint to fetch last N messages from user history (private)
app.get('/history/:tfid/:n?', async (req, res) => {
  try {
    const tfid = req.params.tfid;
    const n = Math.max(1, Math.min(1000, Number(req.params.n || 100)));
    const hist = await readJsonSafe(USER_HISTORY_FILE, { histories: {} });
    const arr = (hist.histories && hist.histories[tfid]) ? hist.histories[tfid] : [];
    res.json(arr.slice(-n));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- /message endpoint (402 handling, continuation & strict regen) ---
app.post('/message', async (req, res) => {
  try {
    const { tfid, sessionId, text } = req.body || {};
    if (!tfid || !sessionId || typeof text !== 'string' || !text.trim()) {
      return res.status(400).json({ error: 'tfid_session_text_required' });
    }

    // verify user & session
    const users = await readJsonSafe(USERS_FILE, { users: [] });
    const user = (users.users || []).find(u => u.tfid === tfid);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    sessionsData.sessions = sessionsData.sessions || {};
    const session = sessionsData.sessions[sessionId];
    if (!session) return res.status(404).json({ error: 'session_not_found' });
    if (session.tfid !== tfid) return res.status(403).json({ error: 'session_belongs_to_other_user' });

    // sanitize user text
    let clean = String(text || '').trim().replace(/\s+/g,' ');
    if (!clean) return res.status(400).json({ error: 'empty_message' });

    // short artifact filter but allow greetings
    const greetingWhitelist = new Set(['hi','hey','hello','salut','bonjour','hola','ola','yo','coucou','alo','heyo']);
    const shortArtifact = /^[A-Za-zÀ-ÖØ-öø-ÿ]{1,2}$/;
    const lc = clean.toLowerCase();
    if (shortArtifact.test(clean) && !greetingWhitelist.has(lc)) {
      const local = `I did not understand "${clean}". Could you please clarify?`;
      session.messages = session.messages || [];
      session.messages.push({ role:'user', content: clean, ts: Date.now() });
      // append to user history
      await appendUserHistory(tfid, { role: 'user', content: clean, sessionId, ts: Date.now() });
      session.messages.push({ role:'assistant', content: local, ts: Date.now() });
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
      await appendUserHistory(tfid, { role: 'assistant', content: local, sessionId, ts: Date.now() });
      return res.json({ assistant: local });
    }

    // append user message to session + user_history
    session.messages = session.messages || [];
    session.messages.push({ role: 'user', content: clean, ts: Date.now() });
    await appendUserHistory(tfid, { role: 'user', content: clean, sessionId, ts: Date.now() });

    // build payload: system + last HISTORY_TAIL messages from this session
    const systemMsg = makeSystemPrompt(tfid, sessionId, user.name || DEFAULT_USER_NAME);
    const history = (session.messages || []).map(m => ({ role: m.role, content: m.content || '' }));
    const tail = history.slice(-HISTORY_TAIL);
    const payloadMessages = [systemMsg, ...tail];

    // provider call loop with smarter 402 handling and low-cost recovery
    let attempt = 0;
    let currentMax = DEFAULT_MAX_TOKENS;
    let lastResp = null;
    let extracted = null;

    while (attempt < MAX_RETRIES) {
      attempt++;
      const payload = {
        model: OPENROUTER_MODEL,
        messages: payloadMessages,
        max_tokens: currentMax,
        max_output_tokens: currentMax,
        temperature: 0.2
      };

      lastResp = await fetchWithTimeout(OPENROUTER_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type':'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
        body: JSON.stringify(payload)
      }, DEFAULT_TIMEOUT_MS);

      // network error
      if (!lastResp.ok && lastResp.fetchError) {
        const fe = lastResp.fetchError;
        const cause = fe && fe.cause ? fe.cause : fe;
        const isENOTFOUND = (cause && cause.code === 'ENOTFOUND') || (String(fe).includes('ENOTFOUND'));
        const details = { message: "Network error contacting OpenRouter", error: String(fe), endpoint: OPENROUTER_ENDPOINT, suggestion: isENOTFOUND ? "DNS failure (ENOTFOUND)." : "Check connectivity" };
        return res.status(502).json({ error: 'network_error', details });
      }

      if (!lastResp.ok) {
        // 402 handling
        if (lastResp.status === 402) {
          let affordable = null;
          const j = lastResp.json;
          if (j && j.error) {
            if (j.error.metadata && typeof j.error.metadata.affordable_tokens === 'number') affordable = j.error.metadata.affordable_tokens;
            else if (typeof j.error.message === 'string') {
              const m = j.error.message.match(/can only afford\s+(\d{2,4})/i) || j.error.message.match(/afford(?:able)?[^\d]*(\d{2,4})/i) || j.error.message.match(/(\d{2,4})\s*tokens?/i);
              if (m) affordable = parseInt(m[1], 10);
            }
          }
          if (!affordable || Number.isNaN(affordable)) affordable = Math.max(MIN_TOKENS, Math.floor(currentMax * 0.6));

          // if affordable is very small -> low-cost recovery
          if (affordable <= RECOVERY_MAX_TOKENS_CAP) {
            const recMax = Math.max(MIN_TOKENS, Math.min(affordable, RECOVERY_MAX_TOKENS_CAP));
            const recoveryMsg = {
              role: 'user',
              content: `Brief summary: give a direct short answer (1 sentence) to the previous request: "${clean}".`
            };
            const shortPayload = { model: OPENROUTER_MODEL, messages: [systemMsg, ...tail.slice(-1), recoveryMsg], max_tokens: recMax, max_output_tokens: recMax, temperature: 0.0 };
            const recoveryResp = await fetchWithTimeout(OPENROUTER_ENDPOINT, {
              method: 'POST',
              headers: { 'Content-Type':'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
              body: JSON.stringify(shortPayload)
            }, DEFAULT_TIMEOUT_MS);
            if (recoveryResp.ok) {
              const recovered = extractAssistantText(recoveryResp.json);
              if (recovered) {
                session.messages.push({ role: 'assistant', content: recovered, ts: Date.now() });
                await writeJsonSafe(SESSIONS_FILE, sessionsData);
                await appendUserHistory(tfid, { role: 'assistant', content: recovered, sessionId, ts: Date.now() });
                return res.json({ assistant: recovered });
              }
            }
            const guidance = `Low credits (${affordable} tokens). Do you want a very short summary?`;
            session.messages.push({ role: 'assistant', content: guidance, ts: Date.now() });
            await writeJsonSafe(SESSIONS_FILE, sessionsData);
            await appendUserHistory(tfid, { role: 'assistant', content: guidance, sessionId, ts: Date.now() });
            return res.json({ assistant: guidance });
          }

          // otherwise reduce currentMax then retry
          const prev = currentMax;
          let next = affordable < currentMax ? Math.max(MIN_TOKENS, Math.min(affordable, currentMax - 1)) : Math.max(MIN_TOKENS, Math.floor(currentMax * 0.75));
          if (next >= prev) break;
          currentMax = next;
          continue;
        }

        // other provider error -> break
        break;
      }

      // lastResp.ok === true: try to extract
      extracted = extractAssistantText(lastResp.json);
      const maybeChoice = lastResp.json?.choices?.[0];
      const finishReason = maybeChoice?.finish_reason || maybeChoice?.native_finish_reason || null;

      if (extracted) break;

      // if truncated, try increasing budget but bounded
      if (finishReason === 'length' || finishReason === 'max_output_tokens') {
        if (currentMax < MAX_ALLOWED_TOKENS) {
          const prev = currentMax;
          currentMax = Math.min(MAX_ALLOWED_TOKENS, Math.max(currentMax + 64, Math.floor(currentMax * 1.8)));
          continue; // retry
        }
      }

      // else fallback to continuation/regeneration outside loop
      break;
    } // end while

    let assistantText = extracted || null;

    // final attempt to extract if provider ok
    if (!assistantText && lastResp && lastResp.ok) assistantText = extractAssistantText(lastResp.json);

    const maybeChoiceFinal = lastResp?.json?.choices?.[0];

    // continuation attempt if truncated and no assistantText
    if (!assistantText && maybeChoiceFinal && (maybeChoiceFinal.finish_reason === 'length' || maybeChoiceFinal.native_finish_reason === 'max_output_tokens')) {
      const continueUser = { role: 'user', content: `Continue and finish the previous answer concisely (1 to 3 sentences). Always finish sentences.` };
      const contMax = Math.max(MIN_TOKENS, Math.min(Math.floor(currentMax / 2), RECOVERY_MAX_TOKENS_CAP));
      const contPayload = { model: OPENROUTER_MODEL, messages: [...payloadMessages, continueUser], max_tokens: contMax, max_output_tokens: contMax, temperature: 0.0 };
      const contResp = await fetchWithTimeout(OPENROUTER_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type':'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
        body: JSON.stringify(contPayload)
      }, DEFAULT_TIMEOUT_MS);
      if (contResp.ok) {
        const contText = extractAssistantText(contResp.json);
        if (contText) {
          session.messages.push({ role: 'assistant', content: contText, ts: Date.now() });
          await writeJsonSafe(SESSIONS_FILE, sessionsData);
          await appendUserHistory(tfid, { role: 'assistant', content: contText, sessionId, ts: Date.now() });
          return res.json({ assistant: contText });
        }
      }
    }

    // strict regeneration if content empty or encrypted reasoning blocks
    if (!assistantText && lastResp && lastResp.json) {
      const rd = lastResp.json?.choices?.[0]?.message?.reasoning_details || [];
      const hasReasoningDetails = Array.isArray(rd) && rd.length > 0;
      const allEncrypted = hasReasoningDetails && rd.every(it => it && it.type && String(it.type).toLowerCase().includes('encrypted'));
      if (allEncrypted || !assistantText) {
        const regenUser = { role: 'user', content: `Provide a clear and brief answer (1 sentence) to: "${clean}". No internal analysis. Finish your sentence.` };
        const regenPayload = {
          model: OPENROUTER_MODEL,
          messages: [systemMsg, ...tail.slice(-1), regenUser],
          max_tokens: Math.max(MIN_TOKENS, Math.min(RECOVERY_MAX_TOKENS_CAP, DEFAULT_MAX_TOKENS)),
          max_output_tokens: Math.max(MIN_TOKENS, Math.min(RECOVERY_MAX_TOKENS_CAP, DEFAULT_MAX_TOKENS)),
          temperature: 0.0
        };
        const regenResp = await fetchWithTimeout(OPENROUTER_ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type':'application/json', 'Authorization': 'Bearer ' + OPENROUTER_API_KEY },
          body: JSON.stringify(regenPayload)
        }, DEFAULT_TIMEOUT_MS);
        if (regenResp.ok) {
          const regenText = extractAssistantText(regenResp.json);
          if (regenText) {
            session.messages.push({ role: 'assistant', content: regenText, ts: Date.now() });
            await writeJsonSafe(SESSIONS_FILE, sessionsData);
            await appendUserHistory(tfid, { role: 'assistant', content: regenText, sessionId, ts: Date.now() });
            return res.json({ assistant: regenText });
          }
        }
      }
    }

    // final fallback concise
    if (!assistantText) {
      const fallback = "Sorry, I couldn't obtain a complete response from the provider.";
      session.messages.push({ role: 'assistant', content: fallback, ts: Date.now() });
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
      await appendUserHistory(tfid, { role: 'assistant', content: fallback, sessionId, ts: Date.now() });
      return res.json({ assistant: fallback });
    }

    // success: save assistant message in session and user history
    session.messages.push({ role: 'assistant', content: assistantText, ts: Date.now() });
    await writeJsonSafe(SESSIONS_FILE, sessionsData);
    await appendUserHistory(tfid, { role: 'assistant', content: assistantText, sessionId, ts: Date.now() });

    return res.json({ assistant: assistantText });

  } catch (err) {
    console.error('/message error', err);
    return res.status(500).json({ error: 'server_error', details: err?.message || String(err) });
  }
});

// health
app.get('/health', (req,res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Proxy server: http://localhost:${PORT}`);
  console.log(`Model: ${OPENROUTER_MODEL}  Endpoint: ${OPENROUTER_ENDPOINT}`);
  console.log(`Defaults: HISTORY_TAIL=${HISTORY_TAIL}, MAX_TOKENS=${DEFAULT_MAX_TOKENS}`);
});
