self.addEventListener('install', e => {
  e.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('message', e => {
  if (e.data && e.data.type === 'UNREGISTER_SW') {
    (async () => {
      const reg = await self.registration.unregister();
      const keys = await caches.keys();
      await Promise.all(keys.map(k => caches.delete(k)));
      const clients = await self.clients.matchAll({ includeUncontrolled: true });
      for (const c of clients) {
        c.postMessage({ type: 'SW_UNREGISTERED', ok: !!reg });
      }
    })();
  }
});
