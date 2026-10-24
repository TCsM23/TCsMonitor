// TCsMonitor service worker.
// Served from /sw.js (not /static/) so it controls the whole site.
//
// Strategy:
//   pages (navigation)  -> network first; if the server is unreachable, show offline.html
//   /static/ files      -> cached copy instantly, refreshed in the background
//   /api/, /ws, /login  -> never cached: monitoring data must always be live
//
// Bump VERSION whenever you change static files so phones pick up the new ones.
const VERSION = "tcsm-v1";
const SHELL = [
  "/static/offline.html",
  "/static/style.css",
  "/static/app.js",
  "/static/chart.umd.min.js",
  "/static/manifest.webmanifest",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {   // delete caches from older versions
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== location.origin) return;  // let the browser handle it

  if (req.mode === "navigate") {
    event.respondWith(fetch(req).catch(() => caches.match("/static/offline.html")));
    return;
  }

  if (url.pathname.startsWith("/static/")) {
    event.respondWith(
      caches.open(VERSION).then(async (cache) => {
        const cached = await cache.match(req);
        const fresh = fetch(req)
          .then((res) => { if (res.ok) cache.put(req, res.clone()); return res; })
          .catch(() => cached);
        return cached || fresh;
      })
    );
  }
  // everything else (/api/..., /login, /logout) goes straight to the network
});
