// sw.js
const CACHE_VERSION = 'v3-adamdh7'; // bump version when changing
const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/sw.js',
  'https://adamdh7ai.pages.dev/asset/1024.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_VERSION)
      .then(cache => cache.addAll(PRECACHE_URLS))
      .catch(()=>{})
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(k => k !== CACHE_VERSION).map(k => caches.delete(k))
    )).then(()=> self.clients.claim())
  );
  // notify clients that SW is active (optional)
  event.waitUntil(
    self.clients.matchAll({type:'window'}).then(clients => {
      clients.forEach(c => {
        try { c.postMessage({ type: 'SW_ACTIVATED', version: CACHE_VERSION }); } catch(e){}
      });
    })
  );
});

function isApiRequest(request){
  try {
    const url = new URL(request.url);
    return url.hostname.endsWith('workers.dev') || url.pathname.startsWith('/api');
  } catch(e){
    return false;
  }
}

function sendMessageToClients(msg){
  self.clients.matchAll({type:'window'}).then(clients=>{
    clients.forEach(c=>{
      try { c.postMessage(msg); } catch(e){}
    });
  });
}

self.addEventListener('fetch', event => {
  const req = event.request;

  // navigation or HTML pages -> network-first with no-store to bypass HTTP cache, fallback to cache
  if (req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html')) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_VERSION);
      const cached = await cache.match(req) || await cache.match('/index.html') || await cache.match('/');
      try {
        const networkReq = new Request(req.url, { method: req.method, headers: req.headers, mode: req.mode, credentials: req.credentials, redirect: req.redirect, referrer: req.referrer, referrerPolicy: req.referrerPolicy, integrity: req.integrity, cache: 'no-store' });
        const res = await fetch(networkReq);
        // update cache
        try { await cache.put(req, res.clone()); } catch(e){}
        // if there was cached content, inform clients that new content arrived
        if (cached) {
          sendMessageToClients({ type: 'NEW_CONTENT_AVAILABLE', url: req.url, version: CACHE_VERSION });
        }
        return res;
      } catch(err){
        return cached || new Response('', { status: 504, statusText: 'offline' });
      }
    })());
    return;
  }

  // API -> network-first (no-store) -> fallback to cache
  if (isApiRequest(req)) {
    event.respondWith((async () => {
      try {
        const networkReq = new Request(req.url, { method: req.method, headers: req.headers, mode: req.mode, credentials: req.credentials, redirect: req.redirect, referrer: req.referrer, referrerPolicy: req.referrerPolicy, integrity: req.integrity, cache: 'no-store' });
        const res = await fetch(networkReq);
        // optionally cache GET API responses
        if (req.method === 'GET') {
          try { const c = await caches.open(CACHE_VERSION); await c.put(req, res.clone()); } catch(e){}
        }
        return res;
      } catch(e){
        const cached = await caches.match(req);
        return cached || new Response('', { status: 504, statusText: 'offline' });
      }
    })());
    return;
  }

  // static assets -> cache-first, but also fetch network in background (no-store) and update cache
  event.respondWith((async () => {
    const cache = await caches.open(CACHE_VERSION);
    const cachedResponse = await cache.match(req);
    // Start background update without blocking the response
    (async () => {
      try {
        const networkReq = new Request(req.url, { method: req.method, headers: req.headers, mode: req.mode, credentials: req.credentials, redirect: req.redirect, referrer: req.referrer, referrerPolicy: req.referrerPolicy, integrity: req.integrity, cache: 'no-store' });
        const networkRes = await fetch(networkReq);
        if (req.method === 'GET' && networkRes && networkRes.ok && networkRes.type !== 'opaque') {
          try { await cache.put(req, networkRes.clone()); } catch(e){}
          // If resource existed in cache and we updated it, notify clients
          if (cachedResponse) sendMessageToClients({ type: 'ASSET_UPDATED', url: req.url, version: CACHE_VERSION });
        }
      } catch(e){}
    })();

    if (cachedResponse) return cachedResponse;
    try {
      const networkReq2 = new Request(req.url, { method: req.method, headers: req.headers, mode: req.mode, credentials: req.credentials, redirect: req.redirect, referrer: req.referrer, referrerPolicy: req.referrerPolicy, integrity: req.integrity, cache: 'no-store' });
      const networkRes2 = await fetch(networkReq2);
      if (req.method === 'GET' && networkRes2 && networkRes2.ok && networkRes2.type !== 'opaque') {
        try { await cache.put(req, networkRes2.clone()); } catch(e){}
      }
      return networkRes2;
    } catch(e) {
      const accept = req.headers.get('accept') || '';
      if (req.destination === 'image' || accept.includes('image')) {
        return caches.match('https://adamdh7ai.pages.dev/asset/1024.png');
      }
      return new Response('', { status: 504, statusText: 'offline' });
    }
  })());
});
