// sw.js
const CACHE_VERSION = 'v1-adamdh7';
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
    ))
  );
  self.clients.claim();
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

  // navigation or HTML pages -> network-first, fallback to cache
  if (req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html')) {
    event.respondWith(
      fetch(req).then(res => {
        try {
          const copy = res.clone();
          caches.open(CACHE_VERSION).then(cache => cache.put(req, copy)).catch(()=>{});
        } catch(e){}
        return res;
      }).catch(() => caches.match(req).then(c => c || caches.match('/index.html') || caches.match('/')))
    );
    return;
  }

  // API -> network-first -> fallback to cache
  if (isApiRequest(req)) {
    event.respondWith(
      fetch(req).then(res => res).catch(() => caches.match(req))
    );
    return;
  }

  // static assets -> cache-first, then network and cache
  event.respondWith(
    caches.match(req).then(cached => {
      if (cached) return cached;
      return fetch(req).then(networkRes => {
        try {
          if (req.method === 'GET' && networkRes && networkRes.type !== 'opaque') {
            const copy = networkRes.clone();
            caches.open(CACHE_VERSION).then(cache => cache.put(req, copy).catch(()=>{}));
          }
        } catch(e){}
        return networkRes;
      }).catch(() => {
        const accept = req.headers.get('accept') || '';
        if (req.destination === 'image' || accept.includes('image')) {
          return caches.match('https://adamdh7ai.pages.dev/asset/1024.png');
        }
        return new Response('', { status: 504, statusText: 'offline' });
      });
    })
  );
});
