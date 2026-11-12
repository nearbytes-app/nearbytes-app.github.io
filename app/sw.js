// The web app's service worker: the host page's (release/web), never part of the signed bundle. It does three things,
// events only, no timer, no poll:
// 1. The files of the bundle the host page verified (spec app-bundle 0.2 §9) are answered from the host's own
//    storage, `nearbytes-bundle-<manifest hash>`: the bundle in use at the site's paths, a bundle staged for an update
//    under `@<manifest hash>/`. Nothing else ever answers for a file of the bundle.
// 2. Every other same-site GET (the host page, its script, the core, the configuration) is answered by the network and
//    kept as it was last seen; with the network gone, what was kept answers, so the app opens on a phone with no signal
//    (bugs/web-app-cannot-open-while-browser-offline). Other sites (the meeting point, the tracker) are never touched.
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

/** Answers `request`: the network's answer, kept; or, with no network, the kept one. */
async function answer(request, caches, fetcher, scope) {
  const own = scope === undefined ? undefined : await ofBundle(typeof request === "string" ? request : request.url, scope, caches);
  if (own) return own;
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
  self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
  self.addEventListener("fetch", (event) => {
    const request = event.request;
    if (request.method !== "GET" || new URL(request.url).origin !== self.location.origin) return;
    event.respondWith(answer(request, self.caches, (r) => fetch(r), self.registration.scope));
  });
}

if (typeof module !== "undefined") module.exports = { answer, ofBundle, woken, clicked, WAKE };
