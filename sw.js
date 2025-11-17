/* sw.js - TF-Stream (corrigé)
   - Cache shell, thumbs (images) ak json
   - NE PAS cache vidéo (mp4, m3u8, webm, mpd, mkv)
   - Lors de fetch: laisser le navigateur gérer les requêtes vidéo
*/

const CACHE_NAME = 'adamdh7ai-shell-v1';
const IMAGE_CACHE = 'adamdh7ai-thumbs-v1';
const JSON_CACHE = 'adamdh7ai-json-v1';
const OFFLINE_URL = '/offline.html';
const PLACEHOLDER = '/asset/192.png';
const PRECACHE_URLS = ['/', '/index.html', '/manifest.json', OFFLINE_URL, PLACEHOLDER];

// Extensions qu'on considère "vidéo" — NE PAS intercepter / cacher ces urls
const VIDEO_REGEX = /\.(mp4|m3u8|webm|mpd|mkv)(\?|$)/i;
// Extensions images / json
const IMAGE_REGEX = /\.(png|jpg|jpeg|webp|gif)(\?|$)/i;

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    // pre-cache shell
    const cache = await caches.open(CACHE_NAME);
    try {
      await Promise.all(PRECACHE_URLS.map(async u => {
        try {
          const res = await fetch(u, { cache: 'no-cache' });
          if (res && (res.ok || res.type === 'opaque')) await cache.put(new Request(u), res.clone());
        } catch (e) {
          // ignore individual precache failures
        }
      }));
    } catch (e) {}

    // try to preload index.json -> cache JSON and thumbs (but skip videos)
    try {
      const resp = await fetch('/index.json', { cache: 'no-cache' });
      if (resp && (resp.ok || resp.type === 'opaque')) {
        const json = await resp.clone().json().catch(()=>null);
        const imageCache = await caches.open(IMAGE_CACHE);
        const jsonCache = await caches.open(JSON_CACHE);

        // Always cache index.json itself
        try { await jsonCache.put(new Request('/index.json'), resp.clone()); } catch(e){}

        const urls = new Set();

        function collectFromItem(it){
          if(!it || typeof it !== 'object') return;
          // thumb fields
          if (it['Url Thumb'] && typeof it['Url Thumb'] === 'string') urls.add(new URL(it['Url Thumb'], self.registration.scope).href);
          if (it.thumb && typeof it.thumb === 'string') urls.add(new URL(it.thumb, self.registration.scope).href);
          // info fields which may refer to json (but skip video)
          if (it.info && typeof it.info === 'string' && it.info.endsWith('.json')) urls.add(new URL(it.info, self.registration.scope).href);
          // Seasons / episodes
          if (Array.isArray(it.Saisons)) {
            it.Saisons.forEach(s => {
              if(!s || typeof s !== 'object') return;
              if (s.description && typeof s.description === 'string' && s.description.endsWith('.json')) urls.add(new URL(s.description, self.registration.scope).href);
              if (Array.isArray(s.episodes)) {
                s.episodes.forEach(ep => {
                  if(!ep || typeof ep !== 'object') return;
                  if (ep.thumbnail && typeof ep.thumbnail === 'string') urls.add(new URL(ep.thumbnail, self.registration.scope).href);
                  if (ep.thumb && typeof ep.thumb === 'string') urls.add(new URL(ep.thumb, self.registration.scope).href);
                  // IMPORTANT: skip ep.video (video files) — do NOT add them
                });
              }
            });
          }
        }

        if (Array.isArray(json)) {
          json.forEach(it => collectFromItem(it));
        } else if (typeof json === 'object' && json !== null) {
          // if object, iterate values
          Object.values(json).forEach(v => {
            if (typeof v === 'object') collectFromItem(v);
            else if (typeof v === 'string') {
              // strings that are images or json
              try {
                const u = new URL(v, self.registration.scope).href;
                if (IMAGE_REGEX.test(u) || v.endsWith('.json')) urls.add(u);
              } catch(e){}
            }
          });
        }

        // fetch & cache collected URLs (images and referenced json), but SKIP videos
        await Promise.all(Array.from(urls).map(async u => {
          try {
            if (VIDEO_REGEX.test(u)) return; // safety: skip video urls
            if (u.endsWith('.json')) {
              const r = await fetch(u, { cache: 'no-cache' });
              if (r && (r.ok || r.type === 'opaque')) await jsonCache.put(new Request(u), r.clone());
            } else if (IMAGE_REGEX.test(u)) {
              // images: use no-cors for cross-origin images to avoid CORS failures (response will be opaque)
              const r = await fetch(u, { mode: 'no-cors' }).catch(()=>null);
              if (r) {
                try { await imageCache.put(new Request(u), r.clone()); } catch(e){}
              }
            }
          } catch (e) {}
        }));
      }
    } catch (e) {
      // ignore index.json preload failures
    }

    await self.skipWaiting();
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    // cleanup old caches
    const expected = [CACHE_NAME, IMAGE_CACHE, JSON_CACHE];
    const keys = await caches.keys();
    await Promise.all(keys.map(k => expected.includes(k) ? Promise.resolve() : caches.delete(k)));
    await self.clients.claim();
  })());
});

async function showNotificationForPayload(payload) {
  const title = payload.title || 'TF-Stream';
  const options = {
    body: payload.body || '',
    icon: payload.icon || PLACEHOLDER,
    badge: payload.badge || (payload.icon || PLACEHOLDER),
    image: payload.image,
    tag: payload.tag || 'tfstream-auto',
    renotify: false,
    data: payload.data || {},
    actions: payload.actions || []
  };
  try { await self.registration.showNotification(title, options); } catch (e) {}
}

self.addEventListener('message', event => {
  const msg = event.data || {};
  if (!msg) return;
  if (msg.type === 'SHOW_NOTIFICATION') {
    showNotificationForPayload(msg.payload || {});
  } else if (msg.type === 'LIST_CACHES') {
    (async () => {
      const keys = await caches.keys();
      event.source && event.source.postMessage({ type: 'CACHES_LIST', keys });
    })();
  }
});

self.addEventListener('periodicsync', event => {
  if (event.tag !== 'tfstream-notifs') return;
  event.waitUntil((async () => {
    let item = null;
    try {
      const jresp = await caches.match('/index.json') || await fetch('/index.json');
      if (jresp) {
        const json = await jresp.json();
        const allowed = ['film','série','serie','anime','animé'];
        let pool = [];
        if (Array.isArray(json)) {
          pool = json.filter(it => { if(!it) return false; const c = (it.Catégorie||it.category||'').toString().toLowerCase(); return allowed.includes(c); });
        } else if (typeof json === 'object') {
          pool = Object.values(json).filter(it => { if(!it||typeof it!=='object') return false; const c = (it.Catégorie||it.category||'').toString().toLowerCase(); return allowed.includes(c); });
        }
        if (pool && pool.length) {
          item = pool[Math.floor(Math.random() * pool.length)];
        } else {
          if (Array.isArray(json) && json.length) item = json[Math.floor(Math.random() * json.length)];
          else if (typeof json === 'object') {
            const keys = Object.keys(json||{}); if (keys.length) item = json[keys[Math.floor(Math.random()*keys.length)]];
          }
        }
      }
    } catch (e) { item = null; }
    const titleBase = item && (item.Titre || item.Name) ? (item.Titre || item.Name).toString().trim() : 'TF-Stream';
    const timeStr = new Date().toLocaleTimeString();
    const body = `${titleBase} ${timeStr}`;
    const image = item && (item['Url Thumb'] || item.thumb) ? new URL(item['Url Thumb'] || item.thumb, self.registration.scope).href : undefined;
    const slug = item && item.__slug ? item.__slug : (titleBase ? titleBase.toString().toLowerCase().replace(/\s+/g,'-') : undefined);
    const dataPayload = { slug };
    await showNotificationForPayload({ title: `TF-Stream vous propose ${titleBase}`, body, image, icon: image || PLACEHOLDER, badge: PLACEHOLDER, tag: 'tfstream-pbg', data: dataPayload });
  })());
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const slug = (event.notification.data && event.notification.data.slug) ? event.notification.data.slug : undefined;
  event.waitUntil((async () => {
    try {
      const all = await clients.matchAll({ type: 'window', includeUncontrolled: true });
      if (all && all.length) {
        for (const c of all) {
          try {
            c.postMessage({ type: 'NOTIFICATION_CLICK', payload: { slug } });
            c.focus();
            return;
          } catch (e) {}
        }
      }
      try {
        const url = new URL('/', self.registration.scope).href;
        const opened = await clients.openWindow(url);
        setTimeout(async () => {
          const newClients = await clients.matchAll({ type: 'window', includeUncontrolled: true });
          for (const nc of newClients) {
            try { nc.postMessage({ type: 'NOTIFICATION_CLICK', payload: { slug } }); } catch (e) {}
          }
        }, 700);
      } catch (e) {}
    } catch (e) {}
  })());
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;

  // If this looks like a video request: DO NOT intercept/cachE it.
  // We simply return early so the browser performs the network request itself.
  // This prevents service worker caching or rewriting of Range requests that break streaming.
  try {
    const url = new URL(req.url);
    if (VIDEO_REGEX.test(url.pathname)) {
      // let browser handle it directly
      return;
    }
  } catch (e) {
    // If URL parsing fails, proceed to normal handling
  }

  // navigation (HTML) -> network-first then cache fallback
  if (req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html')) {
    event.respondWith((async () => {
      try {
        const net = await fetch(req);
        const cache = await caches.open(CACHE_NAME);
        if (net && (net.ok || net.type === 'opaque')) cache.put(req, net.clone());
        return net;
      } catch (e) {
        return caches.match(req) || caches.match(OFFLINE_URL);
      }
    })());
    return;
  }

  // images -> cache-first (IMAGE_CACHE) with network fallback; placeholder fallback
  if (req.destination === 'image' || IMAGE_REGEX.test(req.url)) {
    event.respondWith((async () => {
      const cache = await caches.open(IMAGE_CACHE);
      const cached = await cache.match(req);
      if (cached) return cached;
      try {
        // try network; use no-cors for cross origin images to avoid CORS errors (response will be opaque)
        const resp = await fetch(req);
        if (resp && (resp.ok || resp.type === 'opaque')) {
          try { await cache.put(req, resp.clone()); } catch(e) {}
          return resp;
        }
      } catch (e) {}
      // fallback placeholder
      return caches.match(PLACEHOLDER) || Response.error();
    })());
    return;
  }

  // JSON files -> network-first with cache fallback
  if (req.url.endsWith('.json')) {
    event.respondWith((async () => {
      const cache = await caches.open(JSON_CACHE);
      try {
        const r = await fetch(req);
        if (r && (r.ok || r.type === 'opaque')) { try { await cache.put(req, r.clone()); } catch(e){}; return r; }
      } catch (e) {}
      const c = await cache.match(req) || caches.match(OFFLINE_URL);
      return c;
    })());
    return;
  }

  // other static assets -> cache-first on shell cache, then network
  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    const match = await cache.match(req);
    if (match) return match;
    try {
      const r = await fetch(req);
      if (r && (r.ok || r.type === 'opaque')) {
        try { await cache.put(req, r.clone()); } catch(e) {}
        return r;
      }
    } catch (e) {
      return caches.match(OFFLINE_URL);
    }
    return caches.match(OFFLINE_URL);
  })());
});
