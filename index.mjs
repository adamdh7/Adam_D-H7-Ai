// index.mjs
// ------------------------------------------------------------------
// Adam_D'H7 - Proxy / Chat server (ESM)
// - Idempotency + dedupe: supports clientMsgId and recent identical message window
// - Stores users in user.json and sessions in sessions.json (atomic writes)
// - Calls OpenRouter (OPENROUTER_API_KEY required)
// ------------------------------------------------------------------
// FR + EN comments: les commentaires alternent français/anglais for clarity
// ------------------------------------------------------------------

import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { promises as fs } from 'fs';
import crypto from 'crypto';

dotenv.config();

// Ensure global fetch available (Node 18+). If using older Node install node-fetch v3.
if (typeof globalThis.fetch !== 'function') {
  try {
    const nf = await import('node-fetch');
    globalThis.fetch = nf.default;
  } catch (e) {
    console.error('Global fetch not available and node-fetch could not be imported. Use Node 18+ or add node-fetch v3.');
    throw e;
  }
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);

// Required: set OPENROUTER_API_KEY in .env
const OPENROUTER_API_KEY = (process.env.OPENROUTER_API_KEY || '').trim();
if (!OPENROUTER_API_KEY) {
  console.error('ERROR: OPENROUTER_API_KEY not set in .env. Exiting.');
  process.exit(1);
}

// Optional MASTER_KEY for encrypting per-user API keys
const MASTER_KEY_HEX = (process.env.MASTER_KEY || '').trim();
function hasMasterKey(){ return !!MASTER_KEY_HEX && MASTER_KEY_HEX.length === 64; }
function getMasterKeyBuffer(){ if(!hasMasterKey()) throw new Error('MASTER_KEY missing or invalid (32 bytes hex).'); return Buffer.from(MASTER_KEY_HEX, 'hex'); }
function encryptText(plaintext){
  const key = getMasterKeyBuffer(); const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}:${tag.toString('base64')}:${ciphertext.toString('base64')}`;
}
function decryptText(payload){
  const key = getMasterKeyBuffer();
  const parts = payload.split(':'); if(parts.length !== 3) throw new Error('Invalid encrypted payload');
  const iv = Buffer.from(parts[0],'base64'); const tag = Buffer.from(parts[1],'base64'); const ciphertext = Buffer.from(parts[2],'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv); decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]); return plain.toString('utf8');
}

const MODEL = (process.env.MODEL || 'openai/gpt-5').trim();
const SYSTEM_PROMPT = (process.env.SYSTEM_PROMPT && process.env.SYSTEM_PROMPT.trim()) ||
`You are Adam_D'H7. Created by D'H7 | Tergene. Each chat session is isolated. Be concise. Do not reveal internal chain-of-thought.`;

const USERS_FILE = path.join(__dirname, 'user.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

// Defaults (tweak in .env)
const DEFAULT_MAX_TOKENS = Number(process.env.DEFAULT_MAX_TOKENS || 170);
const DEFAULT_TEMPERATURE = Number(process.env.DEFAULT_TEMPERATURE || 0.2);
const HISTORY_MESSAGE_LIMIT = Number(process.env.HISTORY_MESSAGE_LIMIT || 16);
const DUP_WINDOW_MS = Number(process.env.DUP_WINDOW_MS || 5000); // dedupe identical messages within 5s
const MAX_PASSES = Number(process.env.MAX_PASSES || 2);
const DEV_DEBUG = process.env.DEV_DEBUG === '1';

app.use(cors({ origin: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------------- file helpers / helpers fichiers ----------------
async function readJsonSafe(filePath, defaultValue){
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw || '{}');
  } catch(err) {
    if (err.code === 'ENOENT') {
      await fs.writeFile(filePath, JSON.stringify(defaultValue, null, 2), 'utf8');
      return defaultValue;
    }
    throw err;
  }
}
async function writeJsonSafe(filePath, obj){
  const tmp = filePath + '.tmp';
  const data = JSON.stringify(obj, null, 2);
  await fs.writeFile(tmp, data, 'utf8');
  await fs.rename(tmp, filePath);
}

// ---------------- TFID generator ----------------
const TF_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789';
function generateTFID(){
  const bytes = crypto.randomBytes(7);
  let id = '';
  for (let i = 0; i < 7; i++) id += TF_CHARS[bytes[i] % TF_CHARS.length];
  return id;
}
async function ensureUniqueTFID(){
  const data = await readJsonSafe(USERS_FILE, { users: [] });
  const exist = new Set(data.users.map(u => u.tfid));
  for (let i=0;i<1000;i++){ const c = generateTFID(); if(!exist.has(c)) return c; }
  return 'TF' + crypto.randomUUID().slice(0,5).toUpperCase();
}

// ensure files exist on startup
await readJsonSafe(USERS_FILE, { users: [] });
await readJsonSafe(SESSIONS_FILE, { sessions: {} });

// ---------------- Provider helpers ----------------
function collectStrings(value){
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(v=>collectStrings(v)).join('');
  if (typeof value === 'object') { let out=''; for(const k of Object.keys(value)) out += collectStrings(value[k]); return out; }
  return '';
}
function extractAssistantText(parsed){
  if(!parsed) return null;
  if (Array.isArray(parsed.choices) && parsed.choices.length){
    const c = parsed.choices[0];
    if (c.message && typeof c.message.content === 'string' && c.message.content.trim()) return c.message.content.trim();
    if (c.message && c.message.content){ const s = collectStrings(c.message.content).trim(); if (s) return s; }
    if (typeof c.text === 'string' && c.text.trim()) return c.text.trim();
    if (c.delta) { const s3 = collectStrings(c.delta).trim(); if (s3) return s3; }
    try { return JSON.stringify(c).slice(0,2000); } catch(e){ return null; }
  }
  if (typeof parsed.text === 'string' && parsed.text.trim()) return parsed.text.trim();
  const fallback = collectStrings(parsed).trim();
  if (fallback) return fallback;
  return null;
}

function deepSanitize(obj){
  if (obj==null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(v => deepSanitize(v));
  const copy = {};
  for (const k of Object.keys(obj)) {
    const lower = String(k).toLowerCase();
    if (['logprobs','reasoning','reasoning_details','internal','debug','trace','metadata'].includes(lower)) continue;
    try { copy[k] = deepSanitize(obj[k]); } catch {}
  }
  return copy;
}
function safeSnippetFromParsed(parsed, maxChars=800){ try { const s = JSON.stringify(deepSanitize(parsed)); if (s.length <= maxChars) return s; return s.slice(0,maxChars) + '...'; } catch(e) { return '(unable to make snippet)'; } }

// ---------------- OpenRouter call with 402 fallback ----------------
function parseAllowedTokensFromErrorText(text){
  if(!text) return null;
  let m = text.match(/can only afford\s*(\d+)/i); if(m && m[1]) return Number(m[1]);
  m = text.match(/afford\s*(\d+)/i); if(m && m[1]) return Number(m[1]);
  m = text.match(/maximum.*?(\d+)/i); if(m && m[1]) return Number(m[1]);
  return null;
}

async function postToOpenRouterWithFallback(body, apiKey = OPENROUTER_API_KEY, maxRetries=2){
  const url = 'https://openrouter.ai/api/v1/chat/completions';
  let attempt = 0; let currentBody = { ...body };
  while (attempt <= maxRetries){
    attempt++;
    try {
      console.log(`[openrouter] attempt ${attempt} max_tokens=${currentBody.max_tokens}`);
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type':'application/json', 'Authorization': 'Bearer ' + apiKey },
        body: JSON.stringify(currentBody)
      });
      const textResp = await resp.text();
      let parsed = null;
      try { parsed = JSON.parse(textResp); } catch(e){ parsed = null; }

      if (resp.ok) return { ok:true, status: resp.status, parsed, rawText: textResp };

      if (resp.status === 402){
        console.warn('[openrouter] 402 detected, trying to reduce max_tokens. snippet:', textResp.slice(0,800));
        const allowed = parseAllowedTokensFromErrorText(textResp);
        let newMax = null;
        if (allowed && typeof allowed === 'number') newMax = Math.max(1, Math.min(currentBody.max_tokens - 1, allowed - 20));
        else { newMax = Math.max(1, Math.floor(currentBody.max_tokens * 0.75)); if (newMax > DEFAULT_MAX_TOKENS) newMax = DEFAULT_MAX_TOKENS; }
        if (newMax < currentBody.max_tokens){ currentBody = { ...currentBody, max_tokens: newMax }; await new Promise(r=>setTimeout(r,250)); continue; }
        return { ok:false, status: resp.status, parsed, rawText: textResp };
      }
      return { ok:false, status: resp.status, parsed, rawText: textResp };
    } catch(err){
      console.error('[openrouter] network error attempt', attempt, err);
      if (attempt > maxRetries) return { ok:false, error: String(err) };
      await new Promise(r=>setTimeout(r,200));
    }
  }
  return { ok:false, error: 'exhausted_retries' };
}

// ---------------- Deliberate & refine pipeline ----------------
async function deliberateAndRefine(baseMessagesForApi, apiKeyToUse, userText){
  try {
    const historyLen = baseMessagesForApi.map(m => m.content || '').join(' ').length;
    const contentLen = (userText||'').length + historyLen;
    let passes = 1 + Math.floor(contentLen / 800);
    passes = Math.max(1, Math.min(passes, MAX_PASSES));

    const draftMessages = [
      ...baseMessagesForApi,
      { role:'system', content: `You are Adam_D'H7. Deliberation mode: produce a clear draft answer. Output ONLY the draft.` },
      { role:'user', content: userText || 'Please respond.' }
    ];

    const draftResult = await postToOpenRouterWithFallback({
      model: MODEL, messages: draftMessages, max_tokens: DEFAULT_MAX_TOKENS, temperature: DEFAULT_TEMPERATURE
    }, apiKeyToUse, 1);

    if (!draftResult.ok) return null;
    let draft = extractAssistantText(draftResult.parsed) || '';

    for (let pass = 2; pass <= passes; pass++){
      const refineMessages = [
        ...baseMessagesForApi,
        { role:'system', content: `You are Adam_D'H7. Deliberation pass ${pass}/${passes}: improve previous draft.` },
        { role:'assistant', content: draft },
        { role:'user', content: userText || 'Refine the draft and produce the final improved answer.' }
      ];
      const refineResult = await postToOpenRouterWithFallback({
        model: MODEL, messages: refineMessages, max_tokens: DEFAULT_MAX_TOKENS, temperature: DEFAULT_TEMPERATURE
      }, apiKeyToUse, 1);
      if (!refineResult.ok) break;
      const refined = extractAssistantText(refineResult.parsed);
      if (refined && refined.trim().length>0) draft = refined;
    }
    return draft;
  } catch(e){ console.error('deliberateAndRefine error', e); return null; }
}

// ---------------- Deduplication stores (in-memory ephemeral) ----------------
// clientMsgId seen map: { sessionId => Set(clientMsgId) }
// Also dedupe identical recent messages by checking last user message timestamp/content
const seenClientMsgIds = new Map();
function markClientMsgIdSeen(sessionId, clientMsgId){
  if (!clientMsgId) return;
  let s = seenClientMsgIds.get(sessionId);
  if (!s){ s = new Set(); seenClientMsgIds.set(sessionId, s); }
  s.add(clientMsgId);
  // cleanup TTL (10min)
  setTimeout(()=>{ const cur = seenClientMsgIds.get(sessionId); if(cur){ cur.delete(clientMsgId); if(cur.size===0) seenClientMsgIds.delete(sessionId); }} , 1000 * 60 * 10);
}
function hasClientMsgIdBeenSeen(sessionId, clientMsgId){ if(!clientMsgId) return false; const s = seenClientMsgIds.get(sessionId); return s ? s.has(clientMsgId) : false; }

// ---------------- HTTP endpoints ----------------

// Create user (or return if tfid provided)
app.post('/user', async (req, res) => {
  try {
    const { name, tfid } = req.body || {};
    const data = await readJsonSafe(USERS_FILE, { users: [] });
    if (tfid){
      const found = data.users.find(u => u.tfid === tfid);
      if (found) return res.json(found);
      return res.status(404).json({ error: 'tfid_not_found' });
    }
    const newTF = await ensureUniqueTFID();
    const user = { tfid: newTF, name: name || null, createdAt: new Date().toISOString(), encryptedApiKey: null, profile: {} };
    data.users.push(user); await writeJsonSafe(USERS_FILE, data); return res.json(user);
  } catch(err){ console.error('/user error', err); return res.status(500).json({ error:'server_error', details: err.message }); }
});

app.get('/users', async (req, res) => {
  try { const data = await readJsonSafe(USERS_FILE, { users: [] }); res.json(data.users); } catch(err){ res.status(500).json({ error: err.message }); }
});

// Save user's API key (encrypted with MASTER_KEY)
app.post('/user/apikey', async (req,res) => {
  try {
    const { tfid, apikey } = req.body || {};
    if (!tfid || !apikey) return res.status(400).json({ error:'tfid_and_apikey_required' });
    if (!hasMasterKey()) return res.status(400).json({ error:'server_missing_master_key' });
    const data = await readJsonSafe(USERS_FILE, { users: [] });
    const found = data.users.find(u => u.tfid === tfid);
    if (!found) return res.status(404).json({ error:'user_not_found' });
    found.encryptedApiKey = encryptText(apikey); await writeJsonSafe(USERS_FILE, data); return res.json({ ok:true });
  } catch(err){ console.error('/user/apikey error', err); res.status(500).json({ error:'server_error', details: String(err) }); }
});
app.delete('/user/apikey', async (req,res) => {
  try {
    const { tfid } = req.body || req.query || {};
    if (!tfid) return res.status(400).json({ error:'tfid_required' });
    const data = await readJsonSafe(USERS_FILE, { users: [] });
    const found = data.users.find(u => u.tfid === tfid); if (!found) return res.status(404).json({ error:'user_not_found' });
    found.encryptedApiKey = null; await writeJsonSafe(USERS_FILE, data); return res.json({ ok:true });
  } catch(err){ console.error('/user/apikey delete error', err); res.status(500).json({ error:'server_error', details: err.message }); }
});

// Create session
app.post('/session', async (req, res) => {
  try {
    const { tfid } = req.body || {};
    if (!tfid) return res.status(400).json({ error: 'tfid_required' });
    const users = await readJsonSafe(USERS_FILE, { users: [] });
    const found = users.users.find(u => u.tfid === tfid);
    if (!found) return res.status(404).json({ error: 'user_not_found' });
    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    const sessionId = crypto.randomUUID();
    const session = { sessionId, tfid, createdAt: new Date().toISOString(), messages: [] };
    sessionsData.sessions[sessionId] = session; await writeJsonSafe(SESSIONS_FILE, sessionsData); return res.json({ sessionId, createdAt: session.createdAt });
  } catch(err){ console.error('/session error', err); res.status(500).json({ error:'server_error', details: err.message }); }
});

app.get('/session/:id', async (req,res) => {
  try { const sessionId = req.params.id; const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} }); const s = sessionsData.sessions[sessionId]; if(!s) return res.status(404).json({ error:'session_not_found' }); res.json(s); } catch(err){ res.status(500).json({ error: err.message }); }
});
app.get('/sessions/:tfid', async (req,res) => {
  try { const tfid = req.params.tfid; const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} }); const list = Object.values(sessionsData.sessions).filter(s => s.tfid === tfid); res.json(list.map(s=>({ sessionId: s.sessionId, createdAt: s.createdAt }))); } catch(err){ res.status(500).json({ error: err.message }); }
});

// ---------------- Main message endpoint with dedupe/idempotency ----------------
// body: { tfid, sessionId, text, clientMsgId? }
app.post('/message', async (req, res) => {
  try {
    const { tfid, sessionId, text, clientMsgId } = req.body || {};
    if (!tfid || !sessionId || !text) return res.status(400).json({ error: 'tfid_session_text_required' });

    const users = await readJsonSafe(USERS_FILE, { users: [] });
    const user = users.users.find(u => u.tfid === tfid);
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    const sessionsData = await readJsonSafe(SESSIONS_FILE, { sessions: {} });
    const session = sessionsData.sessions[sessionId];
    if (!session) return res.status(404).json({ error: 'session_not_found' });
    if (session.tfid !== tfid) return res.status(403).json({ error: 'session_belongs_to_other_user' });

    // 1) idempotency by clientMsgId (if client provides it)
    if (clientMsgId && hasClientMsgIdBeenSeen(sessionId, clientMsgId)) {
      console.log(`Duplicate detected by clientMsgId=${clientMsgId} for session=${sessionId} — ignored.`);
      return res.status(200).json({ ok:true, note:'duplicate_ignored_clientMsgId' });
    }

    // 2) dedupe by identical recent user message (window DUP_WINDOW_MS)
    const lastUserMsg = (() => {
      for (let i = session.messages.length - 1; i >= 0; i--) {
        if (session.messages[i].role === 'user') return session.messages[i];
      }
      return null;
    })();

    const now = Date.now();
    if (lastUserMsg && lastUserMsg.content === text && (now - (lastUserMsg.ts || 0)) <= DUP_WINDOW_MS) {
      console.log(`Duplicate detected by content within ${DUP_WINDOW_MS}ms for session=${sessionId} — ignored.`);
      // optional: return last assistant reply if exists
      const lastAssistant = (() => { for (let i = session.messages.length-1;i>=0;i--){ if (session.messages[i].role === 'assistant') return session.messages[i]; } return null; })();
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
      return res.json({ ok:true, note:'duplicate_ignored_recent', assistant: lastAssistant ? lastAssistant.content : null });
    }

    // mark clientMsgId as seen
    if (clientMsgId) markClientMsgIdSeen(sessionId, clientMsgId);

    // push user message
    const userMsg = { role:'user', content: text, ts: now };
    session.messages.push(userMsg);

    // build messages (system + tail)
    const sys = { role:'system', content: SYSTEM_PROMPT + `\nSession id: ${sessionId}\nUser: ${user.tfid}` };
    const history = (session.messages || []).map(m => m.role === 'user' ? { role:'user', content: m.content || '' } : { role:'assistant', content: m.content || '' });
    const tail = history.slice(-HISTORY_MESSAGE_LIMIT);
    const payloadMessages = [sys, ...tail];

    // determine api key to use
    let apiKeyToUse = OPENROUTER_API_KEY;
    if (user.encryptedApiKey && hasMasterKey()) {
      try { apiKeyToUse = decryptText(user.encryptedApiKey); } catch(e){ console.warn('user key decrypt failed, using global key', e); apiKeyToUse = OPENROUTER_API_KEY; }
    }

    // deliberate & refine pipeline
    let finalAnswer = await deliberateAndRefine(payloadMessages, apiKeyToUse, text);
    let parsedForDebug = null;
    let finishReason = null;

    if (!finalAnswer || !finalAnswer.trim()) {
      const result = await postToOpenRouterWithFallback({
        model: MODEL, messages: payloadMessages, max_tokens: DEFAULT_MAX_TOKENS, temperature: DEFAULT_TEMPERATURE
      }, apiKeyToUse, 2);

      if (!result.ok) {
        const snippet = (result.rawText || JSON.stringify(result.parsed) || result.error || '').toString().slice(0,1000);
        console.warn('[proxy] OpenRouter final failure', result.status, snippet);
        await writeJsonSafe(SESSIONS_FILE, sessionsData);
        if (result.status === 402) return res.status(402).json({ error:'openrouter_insufficient_credits', details: snippet });
        return res.status(result.status || 500).json({ error:'openrouter_error', details: snippet });
      }
      parsedForDebug = result.parsed;
      finalAnswer = extractAssistantText(result.parsed) || '(Repons pa klè)';
      try { const c = (result.parsed.choices && result.parsed.choices[0]) || null; finishReason = c && (c.finish_reason || c.native_finish_reason || null); } catch {}
    }

    if (finishReason === 'max_output_tokens' || finishReason === 'length') {
      finalAnswer = `${finalAnswer}\n\n(Note: output truncated by token limit.)`;
    }

    // save assistant message
    if (finalAnswer && finalAnswer.trim()) {
      const assistantMsg = { role:'assistant', content: finalAnswer, ts: Date.now() };
      session.messages.push(assistantMsg);
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
    } else {
      await writeJsonSafe(SESSIONS_FILE, sessionsData);
    }

    const resp = { assistant: finalAnswer };
    if (DEV_DEBUG && parsedForDebug) resp.debug = safeSnippetFromParsed(parsedForDebug, 800);
    return res.json(resp);

  } catch(err){
    console.error('/message error', err);
    return res.status(500).json({ error:'server_error', details: err.message });
  }
});

// Optional: compatibility proxy /openrouter (sanitized)
app.post('/openrouter', async (req,res) => {
  try {
    const bodyToSend = {
      model: req.body.model || MODEL,
      messages: req.body.messages || [],
      max_tokens: typeof req.body.max_tokens === 'number' ? req.body.max_tokens : DEFAULT_MAX_TOKENS,
      temperature: typeof req.body.temperature === 'number' ? req.body.temperature : DEFAULT_TEMPERATURE
    };
    const result = await postToOpenRouterWithFallback(bodyToSend, OPENROUTER_API_KEY, 2);
    if (!result.ok) {
      const snippet = (result.rawText || JSON.stringify(result.parsed) || result.error || '').toString().slice(0,1000);
      if (result.status === 402) return res.status(402).json({ error:'openrouter_insufficient_credits', details: snippet });
      return res.status(result.status || 500).json({ error:'openrouter_error', details: snippet });
    }
    if (result.parsed){
      const safe = deepSanitize(result.parsed);
      if (DEV_DEBUG) return res.status(result.status).json({ sanitized: safe, debug_snippet: safeSnippetFromParsed(result.parsed,1000) });
      return res.status(result.status).json(safe);
    }
    return res.status(result.status).type('text').send('(no parsed response)');
  } catch(err){ console.error('/openrouter proxy error', err); res.status(500).json({ error:'proxy_failed', details: String(err) }); }
});

app.get('/diag', async (req,res) => {
  try { const r = await fetch('https://openrouter.ai/'); const snippet = await r.text().catch(()=>''); res.json({ ok: !!r, status: r.status, snippet: snippet.slice(0,400) }); } catch(err){ res.status(500).json({ ok:false, error: String(err) }); }
});

app.get('/health', (req,res) => res.json({ ok:true }));

process.on('unhandledRejection', (r) => console.error('unhandledRejection', r));
process.on('uncaughtException', (err) => { console.error('uncaughtException', err); process.exit(1); });

app.listen(PORT, () => {
  console.log(`Proxy server listening on http://localhost:${PORT}`);
  console.log('Serving static files from ./public');
});
