
// service-worker.js (mete li nan /service-worker.js sou repo a)
const CACHE_NAME = 'adamdh7-shell-v1';
const IMAGE_CACHE = 'adamdh7-thumbs-v1';
const JSON_CACHE = 'adamdh7-json-v1';
const VIDEO_CACHE = 'adamdh7-videos-v1';
const OFFLINE_URL = '/offline.html';
const PLACEHOLDER = '/images/placeholder-thumb.png';

const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/manifest.json',
  OFFLINE_URL,
  '/styles.css',
  '/main.js',
  PLACEHOLDER
];

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);

    // Precache core assets — use Promise.allSettled pou pa echwe tout enstalasyon si youn pa disponib
    await Promise.allSettled(
      PRECACHE_URLS.map(u =>
        fetch(u, {cache: 'no-cache'}).then(res => {
          if (!res.ok && res.type !== 'opaque') throw new Error(`${u} -> ${res.status}`);
          return cache.put(u, res.clone());
        }).catch(err => {
          console.warn('Precache failed for', u, err);
        })
      )
    );

    // Eseye chaje index.json epi cache thumbs / json referans
    try {
      const resp = await fetch('/index.json', {cache: 'no-cache'});
      if (resp && (resp.ok || resp.type === 'opaque')) {
        const index = await resp.json();
        const imageCache = await caches.open(IMAGE_CACHE);
        const jsonCache = await caches.open(JSON_CACHE);

        const urls = new Set();

        if (Array.isArray(index)) {
          index.forEach(it => {
            if (it['Url Thumb']) urls.add(normalizeUrl(it['Url Thumb']));
            if (it.video) urls.add(normalizeUrl(it.video));
            // ajoute lòt kle si gen
          });
        } else {
          Object.values(index).forEach(v => {
            if (typeof v === 'string' && (v.endsWith('.json') || /\.(jpg|jpeg|png|webp)$/.test(v))) urls.add(normalizeUrl(v));
          });
        }

        await Promise.allSettled(Array.from(urls).map(u => {
          // chwazi ki cache pou mete li
          if (u.endsWith('.json')) {
            return fetch(u).then(r => { if(r.ok||r.type==='opaque') return jsonCache.put(u, r.clone()); }).catch(()=>{});
          }
          if (/\.(jpg|jpeg|png|webp)$/.test(u)) {
            return fetch(u).then(r => { if(r.ok||r.type==='opaque') return imageCache.put(u, r.clone()); }).catch(()=>{});
          }
          return Promise.resolve();
        }));
      }
    } catch (e) {
      console.warn('Failed to fetch index.json during install', e);
    }

    await self.skipWaiting();
  })());
});

self.addEventListener('activate', evt => {
  evt.waitUntil((async () => {
    // retire ansyen caches si ou vle
    const keys = await caches.keys();
    await Promise.all(keys.map(k => {
      if (![CACHE_NAME, IMAGE_CACHE, JSON_CACHE, VIDEO_CACHE].includes(k)) {
        return caches.delete(k);
      }
      return Promise.resolve();
    }));
    await self.clients.claim();
  })());
});

// helper pou normalize (fè wout absoli si nesesè)
function normalizeUrl(u){
  try {
    const url = new URL(u, self.location.origin);
    return url.pathname + url.search;
  } catch(e) {
    return u;
  }
}

self.addEventListener('fetch', event => {
  const req = event.request;

  if (req.method !== 'GET') return;

  // navigation (html): network-first fallback to offline page
  if (req.mode === 'navigate' || (req.headers.get('accept')||'').includes('text/html')) {
    event.respondWith(networkFirst(req));
    return;
  }

  // images: cache-first, fallback to placeholder
  if (req.destination === 'image' || /\.(png|jpg|jpeg|webp|gif)$/.test(req.url)) {
    event.respondWith(cacheFirstWithFallback(req, IMAGE_CACHE, PLACEHOLDER));
    return;
  }

  // json: network-first with cache fallback
  if (req.url.endsWith('.json')) {
    event.respondWith(networkFirst(req, JSON_CACHE));
    return;
  }

  // default: cache-first then network
  event.respondWith(cacheFirst(req));
});

// Strategies
async function cacheFirst(request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);
  if (cached) return cached;
  try {
    const resp = await fetch(request);
    if (resp && (resp.ok || resp.type === 'opaque')) {
      cache.put(request, resp.clone()).catch(()=>{});
    }
    return resp;
  } catch (e) {
    // fallback for navigation already géré, pou lòt asset retounen cached sinon fail
    return caches.match(OFFLINE_URL);
  }
}

async function networkFirst(request, cacheName = CACHE_NAME) {
  const cache = await caches.open(cacheName);
  try {
    const response = await fetch(request);
    if (response && (response.ok || response.type === 'opaque')) {
      cache.put(request, response.clone()).catch(()=>{});
    }
    return response;
  } catch (err) {
    const cached = await cache.match(request) || await caches.match(OFFLINE_URL);
    return cached;
  }
}

async function cacheFirstWithFallback(request, cacheName, fallbackUrl) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);
  if (cached) return cached;
  try {
    const resp = await fetch(request);
    if (resp && (resp.ok || resp.type === 'opaque')) {
      await cache.put(request, resp.clone());
      return resp;
    }
  } catch (e) {
    // ignore
  }
  // si tout echwe, retounen placeholder soti nan cache global la
  return caches.match(fallbackUrl);
              }
