// Tombstone for the Chirpy PWA service worker (cacheName chirpy-20220722.164030).
//
// The old site registered a cache-first worker with no revalidation and no expiry
// that cached every same-origin GET it ever saw. It is still installed in the
// browser of anyone who visited before the rebuild, so without this file they
// would keep being served the 2022 site indefinitely.
//
// This must stay at the ORIGIN ROOT: that was the original registration scope, and
// a worker can only be replaced by a script at its own URL. Deleting the file
// instead of replacing it is not a fix — a 404 on the update check does not
// reliably evict a registration across engines.
//
// Safe to delete once you are confident no stale registrations remain. There is no
// way to measure that from GitHub Pages, so the honest answer is: leave it.

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      for (const key of await caches.keys()) {
        await caches.delete(key);
      }
      await self.registration.unregister();
      // Reload every open tab so the visitor lands on the real site immediately
      // rather than on whatever the dead worker last served them.
      for (const client of await self.clients.matchAll({ type: 'window' })) {
        client.navigate(client.url);
      }
    })(),
  );
});

// Belt and braces: until the unregister completes, never answer from cache.
self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request));
});
