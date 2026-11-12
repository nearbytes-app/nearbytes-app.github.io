// The web app's host page script (spec app-bundle 0.2 §9). The web app is this page, the web port (the core as
// WebAssembly, core/nearbytes_web.wasm, beside it) and the ONE signed application bundle every app runs: this script
// chooses and verifies that bundle as the native core does (app-bundle 0.1 §5), then runs it. What is per platform lives
// here and in config.json, never in the bundle's files: the tracker's address, the content-security policy (index.html),
// the bundle's identity and the core's (`globalThis.nearbytesHost`, read by app/src/web/host.ts).
//
// At each start, once: the site's bundle/version.json names the bundle; its manifest and signature are fetched and
// checked by the core's own check (`nb_bundle_check`: the release key the core ships, the revocations, layer and
// platform, the core API); each file is fetched and its length and SHA-256 checked against the manifest; only then is
// anything kept, in the host's storage (`nearbytes-bundle-<manifest hash>`, written whole, its marker last), and run.
// The site not answering, or a bundle refused, runs the last bundle kept (verified again), as a native app does. Events
// only: no timer, no poll.

const BUNDLE = "nearbytes-bundle-";
const HOST = "nearbytes-host";
const DEFAULT_SIGNAL = "wss://nearbytes.make-become.workers.dev";
const here = new URL("./", location.href);
const text = new TextDecoder();
const status = (words) => {
  const p = document.getElementById("status");
  if (p) p.textContent = words;
};

const hex = (buffer) => [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (bytes) => hex(await crypto.subtle.digest("SHA-256", bytes));
// newer: begin. Whether version a comes after version b in the precedence of semantic versioning (semver.org, section
// 11): numbers first; a pre-release (1.0.0-beta.2) before its release (1.0.0); pre-release identifiers one by one,
// numbers as numbers and before words, a longer list after its own prefix; build metadata (+...) ignored
// (todos/app-bundle-packages-carry-version-1-0). A text that is no version is never newer, nor older than one.
const newer = (a, b) => {
  const parse = (v) => {
    const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(String(v));
    return m && { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] === undefined ? [] : m[4].split(".") };
  };
  const x = parse(a);
  const y = parse(b);
  if (!x) return false;
  if (!y) return true;
  for (let i = 0; i < 3; i++) if (x.core[i] !== y.core[i]) return x.core[i] > y.core[i];
  if (x.pre.length === 0 || y.pre.length === 0) return x.pre.length === 0 && y.pre.length > 0;
  for (let i = 0; i < Math.min(x.pre.length, y.pre.length); i++) {
    const [p, q] = [x.pre[i], y.pre[i]];
    if (p === q) continue;
    const [pn, qn] = [/^\d+$/.test(p), /^\d+$/.test(q)];
    if (pn && qn) return Number(p) > Number(q);
    if (pn !== qn) return qn;
    return p > q;
  }
  return x.pre.length > y.pre.length;
};
// newer: end.
const types = { html: "text/html", js: "text/javascript", mjs: "text/javascript", css: "text/css", json: "application/json", webmanifest: "application/manifest+json", png: "image/png", svg: "image/svg+xml", ico: "image/x-icon", woff2: "font/woff2", woff: "font/woff", wasm: "application/wasm", txt: "text/plain" };
const typeOf = (path) => types[path.split(".").pop()] ?? "application/octet-stream";

/** The web port's check of a bundle's manifest: the core's own (`nb_bundle_check`). */
async function port() {
  const response = await fetch(new URL("core/nearbytes_web.wasm", here), { cache: "no-cache" });
  if (!response.ok) throw new Error(`the app's core could not be loaded (${response.status})`);
  const bytes = await response.arrayBuffer();
  const module = await WebAssembly.compile(bytes);
  // This instance only checks a signature: it asks the system for nothing.
  const imports = { wasi_snapshot_preview1: {} };
  for (const i of WebAssembly.Module.imports(module)) imports[i.module][i.name] = () => 52;
  const x = (await WebAssembly.instantiate(module, imports)).exports;
  const check = (signature, manifest) => {
    const given = new Uint8Array(64 + manifest.length);
    given.set(signature);
    given.set(manifest, 64);
    const at = x.nb_alloc(given.length);
    new Uint8Array(x.memory.buffer, at, given.length).set(given);
    const status = x.nb_bundle_check(at, given.length);
    x.nb_free(at, given.length);
    const answer = text.decode(new Uint8Array(x.memory.buffer, x.nb_answer(), x.nb_answer_len()));
    if (status !== 0) throw new Error(answer);
    return JSON.parse(answer);
  };
  return { check, core: await sha256(bytes) };
}

async function config() {
  try {
    const r = await fetch(new URL("config.json", here), { cache: "no-cache" });
    return r.ok ? await r.json() : {};
  } catch {
    return {};
  }
}

async function main() {
  const given = await config();
  const signal = typeof given.signal === "string" ? given.signal : DEFAULT_SIGNAL;
  const site = new URL(typeof given.bundle === "string" ? given.bundle : "../bundle/", here);
  const file = (p) => new URL(p, site);
  const { check, core } = await port();
  if (!("serviceWorker" in navigator)) throw new Error("this browser cannot keep the app's files");
  await navigator.serviceWorker.register(new URL("sw.js", here));
  await navigator.serviceWorker.ready;
  if (!navigator.serviceWorker.controller) {
    await new Promise((resolve) => {
      navigator.serviceWorker.addEventListener("controllerchange", resolve, { once: true });
      if (navigator.serviceWorker.controller) resolve();
    });
  }
  const host = await caches.open(HOST);
  const pointer = new URL("__current", here).href;

  const bytesOf = async (response) => new Uint8Array(await response.arrayBuffer());
  const fetchBytes = async (url) => {
    const r = await fetch(url, { cache: "no-cache" });
    if (!r.ok) throw new Error(`${url}: ${r.status}`);
    return bytesOf(r);
  };

  /** A bundle kept whole: its manifest, signature and files, verified again; null when none, or refused. */
  const kept = async (hash) => {
    const cache = await caches.open(BUNDLE + hash);
    const done = await cache.match(new URL("__done", here));
    if (!done) return null;
    const manifest = await bytesOf(await cache.match(new URL("__manifest", here)));
    const signature = await bytesOf(await cache.match(new URL("__signature", here)));
    if ((await sha256(manifest)) !== hash) return null;
    const m = check(signature, manifest);
    const html = await cache.match(new URL(m.run, here));
    return html ? { hash, version: m.version, html: await html.text() } : null;
  };

  /** The bundle `hash`, fetched, verified and kept (§9), or the one already kept. */
  const ensure = async (hash) => {
    const had = await kept(hash).catch(() => null);
    if (had) return had;
    const manifest = await fetchBytes(file(`${hash}/release.json`));
    const signature = await fetchBytes(file(`${hash}/release.sig`));
    if ((await sha256(manifest)) !== hash) throw new Error("the manifest is not the one named");
    const m = check(signature, manifest);
    await caches.delete(BUNDLE + hash);
    const cache = await caches.open(BUNDLE + hash);
    const before = await inUse();
    await Promise.all(
      m.files.map(async (f) => {
        const reused = before?.files.get(f.path);
        let body = reused?.sha === f.sha256 ? reused.bytes : null;
        body ??= await fetchBytes(file(`files/${f.sha256}`));
        if (body.length !== f.size || (await sha256(body)) !== f.sha256) throw new Error(`${f.path} is not the file the signature covers`);
        await cache.put(new URL(f.path, here), new Response(body, { headers: { "content-type": typeOf(f.path) } }));
      }),
    );
    await cache.put(new URL("__manifest", here), new Response(manifest));
    await cache.put(new URL("__signature", here), new Response(signature));
    await cache.put(new URL("__done", here), new Response(m.version));
    const html = await (await cache.match(new URL(m.run, here))).text();
    return { hash, version: m.version, html };
  };

  /** The files of the bundle in use, by path, for the unchanged ones not to be fetched again. */
  const inUse = async () => {
    const p = await host.match(pointer);
    const hash = p ? (await p.text()).trim() : "";
    if (!/^[0-9a-f]{64}$/.test(hash)) return null;
    try {
      const cache = await caches.open(BUNDLE + hash);
      const manifest = await bytesOf(await cache.match(new URL("__manifest", here)));
      const m = JSON.parse(text.decode(manifest));
      const files = new Map();
      for (const f of m.files) files.set(f.path, { sha: f.sha256, bytes: await bytesOf(await cache.match(new URL(f.path, here))) });
      return { hash, files };
    } catch {
      return null;
    }
  };
  const latest = async () => {
    const r = await fetch(file("version.json"), { cache: "no-store" });
    if (!r.ok) throw new Error(`version.json: ${r.status}`);
    const m = (await r.json()).manifest;
    return typeof m === "string" && /^[0-9a-f]{64}$/.test(m) ? m : null;
  };

  // The choice, once (§5): the site's bundle when it verifies and is not older than the one kept; else the one kept.
  const current = await inUse();
  let chosen = current ? await kept(current.hash).catch(() => null) : null;
  try {
    const hash = await latest();
    if (hash !== null && hash !== chosen?.hash) {
      const fresh = await ensure(hash);
      if (chosen === null || newer(fresh.version, chosen.version)) chosen = fresh;
      else console.warn(`Nearbytes: the bundle ${fresh.version} is not newer than the one kept, ${chosen.version}: refused`);
    }
  } catch (e) {
    console.warn(`Nearbytes: the site's bundle was not taken: ${e.message}`);
  }
  if (chosen === null) throw new Error("no application bundle could be verified");
  console.info(`Nearbytes: the app bundle ${chosen.version} (${chosen.hash.slice(0, 12)}), signature verified`);
  await host.put(pointer, new Response(chosen.hash));
  for (const name of await caches.keys()) if (name.startsWith(BUNDLE) && name !== BUNDLE + chosen.hash) await caches.delete(name);

  globalThis.nearbytesHost = {
    build: chosen.hash,
    core,
    signal,
    latest: async () => latest(),
    stage: async (hash) => {
      const staged = await ensure(hash);
      return { html: staged.html, base: new URL(`@${hash}/`, here).href };
    },
    adopt: async (hash) => {
      await host.put(pointer, new Response(hash));
    },
  };
  run(chosen.html);
}

/** Puts the bundle's page in this one, its scripts made to run; this page's own head (the policy) stays. */
function run(html) {
  const doc = new DOMParser().parseFromString(html, "text/html");
  for (const a of doc.documentElement.attributes) document.documentElement.setAttribute(a.name, a.value);
  const live = (el) => {
    if (el.tagName !== "SCRIPT") return document.importNode(el, true);
    const s = document.createElement("script");
    for (const a of el.attributes) s.setAttribute(a.name, a.value);
    s.textContent = el.textContent;
    return s;
  };
  document.title = doc.title;
  for (const el of [...doc.head.children]) if (el.tagName !== "TITLE") document.head.append(live(el));
  document.body.replaceChildren();
  for (const a of [...document.body.attributes]) document.body.removeAttribute(a.name);
  for (const a of doc.body.attributes) document.body.setAttribute(a.name, a.value);
  for (const el of [...doc.body.childNodes]) document.body.append(el.nodeType === 1 ? live(el) : document.importNode(el, true));
}

main().catch((e) => {
  console.error(`Nearbytes: ${e.message}`);
  status(`Nearbytes could not open: ${e.message}.`);
});
