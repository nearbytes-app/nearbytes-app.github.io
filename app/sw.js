// The web app's service worker: the host page's (release/web), never part of the signed bundle. It does three things,
// events only, no timer, no poll:
// 1. The files of the bundle the host page verified (spec app-bundle 0.2 §9) are answered from the host's own
//    storage, `nearbytes-bundle-<manifest hash>`: the bundle in use at the site's paths, a bundle staged for an update
//    under `@<manifest hash>/`. Nothing else ever answers for a file of the bundle.
// 2. Every other same-site GET (the host page, its script, the core, the configuration) is answered from what was kept,
//    at once, and fetched again behind it, the good answer kept for the next time: the network is never waited on when
//    something was kept, so the app opens on a phone with no signal (bugs/web-app-cannot-open-while-browser-offline),
//    whatever the site does (bugs/web-app-does-not-open-from-kept), and while the browser's requests hang with no
//    answer (bugs/web-app-never-opens-while-browser-s: the owner's iPhone, beta 57, a fetch that never returned kept the
//    page from opening). What was never kept, and a request that must not be stored (bundle/version.json, `no-store`), is
//    answered by the network, and kept when good; with the network gone or the site's error, what was kept answers.
//    Other sites (the meeting point, the tracker) are never touched.
// 3. A wake from the meeting point (meeting-point 0.2 §7), which carries nothing, is told as "New activity" unless a
//    window of the app is open (that one syncs and tells in its own words); a click on it brings a window of the app, or opens one. The words are made
//    here, on the device: a closed tab holds no unlocked home, so it reads nothing (logic/lock.ts NEW_ACTIVITY).
const KEPT = "nearbytes-site";
const HOST = "nearbytes-host";
const BUNDLE = "nearbytes-bundle-";
/** The host's own files, which the bundle never shadows. */
const OWN = /^(|index\.html|host\.js|sw\.js|config\.json|core\/.*)$/;

/** The hash of the bundle in use: what the host page kept under the pointer (host.js). */
async function current(caches, scope) {
  const pointer = await (await caches.open(HOST)).match(`${scope}__current`);
  const text = pointer ? (await pointer.text()).trim() : "";
  return /^[0-9a-f]{64}$/.test(text) ? text : null;
}

/** The bundle's answer for `url` (a string) under `scope`, or undefined when the bundle has none. */
async function ofBundle(url, scope, caches) {
  if (!url.startsWith(scope)) return undefined;
  const path = decodeURIComponent(new URL(url).pathname.slice(new URL(scope).pathname.length));
  const staged = /^@([0-9a-f]{64})\/(.*)$/.exec(path);
  if (staged === null && OWN.test(path)) return undefined;
  const hash = staged ? staged[1] : await current(caches, scope);
  if (hash === null) return undefined;
  const file = staged ? staged[2] : path;
  return (await caches.open(BUNDLE + hash)).match(`${scope}${file === "" ? "index.html" : file}`);
}

/**
 * Answers `request`: what was kept, at once, the network's answer fetched behind it and kept when good (`later` keeps the
 * worker alive for it); or, when nothing was kept or the request must not be stored, the network's good answer, kept;
 * with no network or an error from the site, the kept one.
 */
async function answer(request, caches, fetcher, scope, later = (p) => p.catch(() => {})) {
  const own = scope === undefined ? undefined : await ofBundle(typeof request === "string" ? request : request.url, scope, caches);
  if (own) return own;
  const kept = await caches.open(KEPT);
  const stored = typeof request === "string" || request.cache !== "no-store";
  const had = stored ? await kept.match(request) : undefined;
  if (had) {
    later(
      Promise.resolve()
        .then(() => fetcher(request))
        .then((fresh) => (fresh.ok ? kept.put(request, fresh) : undefined))
        .catch(() => {}),
    );
    return had;
  }
  try {
    const fresh = await fetcher(request);
    if (fresh.ok) {
      await kept.put(request, fresh.clone());
      return fresh;
    }
    // An error from the site (not a redirect, which is no failure): what was kept, if anything.
    return (fresh.status >= 400 && (await kept.match(request))) || fresh;
  } catch (e) {
    const old = await kept.match(request);
    if (old) return old;
    throw e;
  }
}

/** At the first visit the page and its script came before this worker: kept now, so that the app opens from what
 * the device holds at the very next visit, whatever answers (identity 0.5 §4.5); what is not answered now is left for the next answer. */
async function keepHost(caches, fetcher, scope) {
  const kept = await caches.open(KEPT);
  await Promise.all([scope, `${scope}host.js`, `${scope}config.json`, `${scope}core/nearbytes_web.wasm`].map(async (url) => {
    if (await kept.match(url)) return;
    const fresh = await fetcher(url).catch(() => null);
    if (fresh?.ok) await kept.put(url, fresh);
  }));
}

/** The notification a wake shows, the lock's words (logic/lock.ts NEW_ACTIVITY); one at a time, a later one replacing it. */
const WAKE = { title: "Nearbytes", body: "New activity", tag: "nearbytes-wake" };

/** A wake arrived: told, unless a window of the app is open (it syncs, and notifies in its own words, by itself). */
async function woken(clients, registration) {
  const open = await clients.matchAll({ type: "window", includeUncontrolled: true });
  if (open.some((c) => c.url.startsWith(registration.scope))) return false;
  await registration.showNotification(WAKE.title, { body: WAKE.body, tag: WAKE.tag, icon: `${registration.scope}icons/icon-192.png` });
  return true;
}

/** The notification was clicked: a window of the app brought forward, else the app opened. */
async function clicked(notification, clients, scope) {
  notification.close();
  const open = await clients.matchAll({ type: "window", includeUncontrolled: true });
  const mine = open.find((c) => c.url.startsWith(scope));
  if (mine) return mine.focus();
  return clients.openWindow(scope);
}

if (typeof self !== "undefined" && self.addEventListener) {
  self.addEventListener("push", (event) => event.waitUntil(woken(self.clients, self.registration)));
  self.addEventListener("notificationclick", (event) => event.waitUntil(clicked(event.notification, self.clients, self.registration.scope)));
  self.addEventListener("install", () => self.skipWaiting());
  self.addEventListener("activate", (event) => event.waitUntil(Promise.all([
    self.clients.claim(),
    keepHost(self.caches, (r) => fetch(r, { cache: "no-cache" }), self.registration.scope).catch(() => {}),
  ])));
  self.addEventListener("fetch", (event) => {
    const request = event.request;
    if (request.method !== "GET" || new URL(request.url).origin !== self.location.origin) return;
    // no-cache: the refresh behind the kept answer is revalidated each time. A newer host is taken at the next start; a
    // newer bundle is taken by the page itself, without a reload (web/update.ts).
    event.respondWith(answer(request, self.caches, (r) => fetch(r, { cache: "no-cache" }), self.registration.scope, (p) => event.waitUntil(p)));
  });
}

if (typeof module !== "undefined") module.exports = { answer, ofBundle, keepHost, woken, clicked, WAKE };
