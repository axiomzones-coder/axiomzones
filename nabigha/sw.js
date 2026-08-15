// نابغة (Nabigha) — Service Worker
// Basic offline-first cache for the app shell.
// NOTE: once deployed to Cloudflare Pages, bump CACHE_NAME on every release
// to force clients to pick up the new version.

const CACHE_NAME = 'nabigha-v1';
const APP_SHELL = [
  './nabigha-v3-secure.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.mode === 'navigate') {
    // Network-first for navigation, so users always get the latest HTML when online.
    event.respondWith(
      fetch(event.request).catch(() => caches.match('./nabigha-v3-secure.html'))
    );
    return;
  }
  // Cache-first for everything else (icons, manifest).
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request))
  );
});
