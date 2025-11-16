// sw.js
const CACHE_VERSION = 'v7-adamdh7';
const PRECACHE_URLS = [
  '/',
  'index.html',
  'sw.js',
  '/manifest.json',
  'https://adamdh7ai.pages.dev/asset/512.png'
];

function sendMessageToClients(msg){
  self.clients.matchAll({type:'window'}).then(clients=>{
    clients.forEach(c=>{
      try { c.postMessage(msg); } catch(e){}
    });
  });
}

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
  event.waitUntil(
    self.clients.matchAll({type:'window'}).then(clients => {
      clients.forEach(c => {
        try { c.postMessage({ type: 'SW_ACTIVATED', version: CACHE_VERSION }); } catch(e){}
      });
    })
  );
});

self.addEventListener('message', event => {
  const data = event.data || {};
  if (data && data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

function isApiRequest(request){
  try {
    const url = new URL(request.url);
    return url.hostname.endsWith('workers.dev') || url.pathname.startsWith('/api');
  } catch(e){
    return false;
  }
}

self.addEventListener('fetch', event => {
  const req = event.request;

  if (req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html')) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_VERSION);
      const cached = await cache.match(req) || await cache.match('/index.html') || await cache.match('/');
      try {
        const networkReq = new Request(req.url, { method: req.method, headers: req.headers, mode: req.mode, credentials: req.credentials, redirect: req.redirect, referrer: req.referrer, referrerPolicy: req.referrerPolicy, integrity: req.integrity, cache: 'no-store' });
        const res = await fetch(networkReq);
        try { await cache.put(req, res.clone()); } catch(e){}
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

  if (isApiRequest(req)) {
    event.respondWith((async () => {
      try {
        const networkReq = new Request(req.url, { method: req.method, headers: req.headers, mode: req.mode, credentials: req.credentials, redirect: req.redirect, referrer: req.referrer, referrerPolicy: req.referrerPolicy, integrity: req.integrity, cache: 'no-store' });
        const res = await fetch(networkReq);
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

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_VERSION);
    const cachedResponse = await cache.match(req);
    (async () => {
      try {
        const networkReq = new Request(req.url, { method: req.method, headers: req.headers, mode: req.mode, credentials: req.credentials, redirect: req.redirect, referrer: req.referrer, referrerPolicy: req.referrerPolicy, integrity: req.integrity, cache: 'no-store' });
        const networkRes = await fetch(networkReq);
        if (req.method === 'GET' && networkRes && networkRes.ok && networkRes.type !== 'opaque') {
          try { await cache.put(req, networkRes.clone()); } catch(e){}
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
