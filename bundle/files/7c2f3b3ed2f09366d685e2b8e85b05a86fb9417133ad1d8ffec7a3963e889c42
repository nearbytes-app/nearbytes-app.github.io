// The web app's offline copy (bugs/web-app-cannot-open-while-browser-offline): every same-site GET (the page, its
// scripts and styles, the core, version.json) is answered by the network and kept as it was last seen; with the
// network gone, what was kept answers, so the app opens on a phone with no signal and finds the hubs kept in the
// browser. Events only: no timer, no poll. Other sites (the meeting point, the tracker) are never touched.
const KEPT = "nearbytes-site";

/** Answers `request`: the network's answer, kept; or, with no network, the kept one. */
async function answer(request, caches, fetcher) {
  const kept = await caches.open(KEPT);
  try {
    const fresh = await fetcher(request);
    if (fresh.ok) await kept.put(request, fresh.clone());
    return fresh;
  } catch (e) {
    const old = await kept.match(request);
    if (old) return old;
    throw e;
  }
}

if (typeof self !== "undefined" && self.addEventListener) {
  self.addEventListener("install", () => self.skipWaiting());
  self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
  self.addEventListener("fetch", (event) => {
    const request = event.request;
    if (request.method !== "GET" || new URL(request.url).origin !== self.location.origin) return;
    event.respondWith(answer(request, self.caches, (r) => fetch(r)));
  });
}

if (typeof module !== "undefined") module.exports = { answer };
