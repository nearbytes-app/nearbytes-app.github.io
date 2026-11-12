#!/bin/sh
# Installs the Nearbytes app on a Mac or a Linux computer, for this person only, with no administrator rights:
#
#   curl -fsSL https://nearbytes-app.github.io/install.sh | sh
#
# It fetches the app's release for this computer from the public site (update 0.4 §6.2: releases/<platform>/core/,
# release.json, release.sig and each file named by its SHA-256), and checks it as the app's own updater does (update
# 0.4 §2), before anything is written where the person will run it:
#
#   1. the release key is not revoked: the meeting point's list (§2.1), a revocation counted only when it verifies;
#   2. release.sig is the Ed25519 signature (RFC 8032, verified strictly: S below the group order, neither the key nor R
#      of small order) of "nearbytes/update/0.2/release", a byte 0, then release.json's bytes exactly as fetched, under
#      the release key below, the same public key the apps ship (crates/nearbytes-update/src/lib.rs, RELEASE_KEY);
#   3. the manifest's format, layer ("core") and platform are this computer's;
#   4. each file's length and SHA-256 are the manifest's.
#
# The first failure stops it and nothing is installed. The signature is checked with what each system ships:
# on Linux by OpenSSL 3 (`openssl pkeyutl -verify -rawin`), the manifest read by Python 3; on macOS, whose LibreSSL has
# no Ed25519, by the short verifier below, run by the system's own JavaScript (osascript), over a SHA-512 made by
# LibreSSL. HTTPS is not trusted for integrity: only the signature is.
#
# Where it installs: macOS ~/Applications/Nearbytes.app; Linux ~/.local/share/nearbytes/app, a command
# ~/.local/bin/nearbytes and a menu entry ~/.local/share/applications/nearbytes.desktop. The app's data is not touched.
#
# For tests only: NEARBYTES_SITE names another site, NEARBYTES_INSTALL_TEST_KEY another release key (hexadecimal),
# NEARBYTES_REVOKED_URL another list of revocations (empty: none is read).
set -eu

SITE=${NEARBYTES_SITE:-https://nearbytes-app.github.io}
KEY=${NEARBYTES_INSTALL_TEST_KEY:-027fd97767893fdc0bcbaedf04c3a37445147c4262fd6c72ed6633af0c1191a4}
REVOKED_URL=${NEARBYTES_REVOKED_URL-https://nearbytes.make-become.workers.dev/release/revoked}
LABEL_RELEASE="nearbytes/update/0.2/release"
LABEL_REVOKE="nearbytes/update/0.3/revoke"

say() { printf '%s\n' "$*"; }
stop() { printf 'Nearbytes was not installed: %s\n' "$*" >&2; exit 1; }

case $KEY in
  *[!0-9a-f]*) stop "the release key is not hexadecimal" ;;
esac
[ ${#KEY} -eq 64 ] || stop "the release key is not 32 bytes"

case $(uname -s) in
  Darwin) os=macos ;;
  Linux) os=linux ;;
  *) stop "this script is for macOS and Linux; on Windows use the PowerShell command on the page" ;;
esac
case $(uname -m) in
  arm64 | aarch64) arch=aarch64 ;;
  x86_64 | amd64) arch=x86_64 ;;
  *) stop "no build for this processor ($(uname -m))" ;;
esac
platform=$os-$arch
command -v curl > /dev/null || stop "curl is needed"
command -v openssl > /dev/null || stop "openssl is needed"
if [ "$os" = linux ]; then
  command -v python3 > /dev/null || stop "python3 is needed to read the release"
  openssl version | grep -q '^OpenSSL [3-9]' || stop "OpenSSL 3 or later is needed to check the signature"
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/nearbytes-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

tohex() { od -An -v -tx1 | tr -d ' \n'; }
# Writes the bytes a hexadecimal text names (POSIX printf, octal escapes: no xxd needed).
hexbytes() {
  h=$1 out=""
  while [ -n "$h" ]; do
    b=${h%"${h#??}"}
    h=${h#??}
    out="$out\\$(printf '%03o' "0x$b")"
  done
  # shellcheck disable=SC2059
  printf "$out"
}
sha256() { openssl dgst -sha256 -binary < "$1" | tohex; }

# The verifier for macOS: Ed25519 verification as RFC 8032 §5.1.7 gives it, cofactorless and strict, in the system's
# JavaScript; the SHA-512 is LibreSSL's, made by the caller. It also reads the manifest and the list of revocations as
# JSON. Nothing here decides alone: every check is made again by the shell on what it prints.
cat > "$tmp/check.js" << 'JS'
ObjC.import("Foundation");
const P = (1n << 255n) - 19n, L = (1n << 252n) + 27742317777372353535851937790883648493n;
const md = (a, m = P) => ((a % m) + m) % m;
function pw(b, e, m = P) { let r = 1n; b = md(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
const inv = (a) => pw(a, P - 2n);
const D = md(-121665n * inv(121666n)), I = pw(2n, (P - 1n) / 4n);
function bytes(h) { if (!/^([0-9a-f]{2})*$/.test(h)) throw new Error("not hexadecimal"); const b = []; for (let i = 0; i < h.length; i += 2) b.push(parseInt(h.slice(i, i + 2), 16)); return b; }
const le = (b) => b.reduceRight((n, x) => (n << 8n) | BigInt(x), 0n);
function add(p, q) {
  const a = md((p[1] - p[0]) * (q[1] - q[0])), b = md((p[1] + p[0]) * (q[1] + q[0]));
  const c = md(2n * D * p[3] * q[3]), d = md(2n * p[2] * q[2]);
  const e = b - a, f = d - c, g = d + c, h = b + a;
  return [md(e * f), md(g * h), md(f * g), md(e * h)];
}
function mul(n, p) { let r = [0n, 1n, 1n, 0n], q = p; while (n > 0n) { if (n & 1n) r = add(r, q); q = add(q, q); n >>= 1n; } return r; }
function enc(p) { const z = inv(p[2]), x = md(p[0] * z), y = md(p[1] * z); let n = y | ((x & 1n) << 255n), s = ""; for (let i = 0; i < 32; i++) { s += Number(n & 255n).toString(16).padStart(2, "0"); n >>= 8n; } return s; }
function dec(h) {
  const n = le(bytes(h)), sign = n >> 255n, y = n & ((1n << 255n) - 1n);
  if (y >= P) return null;
  const y2 = y * y % P, x2 = md((y2 - 1n) * inv(D * y2 + 1n));
  if (x2 === 0n) return sign ? null : [0n, y, 1n, 0n];
  let x = pw(x2, (P + 3n) / 8n);
  if (md(x * x - x2) !== 0n) x = x * I % P;
  if (md(x * x - x2) !== 0n) return null;
  if ((x & 1n) !== sign) x = P - x;
  return [x, y, 1n, x * y % P];
}
const small = (p) => enc(mul(8n, p)) === "01" + "00".repeat(31);
const B = dec("58" + "66".repeat(31));
function verify(pub, sig, h) {
  if (pub.length !== 64 || sig.length !== 128 || h.length !== 128) return false;
  const A = dec(pub), R = dec(sig.slice(0, 64));
  if (A === null || R === null || small(A) || small(R)) return false;
  const S = le(bytes(sig.slice(64)));
  if (S >= L) return false;
  const k = mul(le(bytes(h)) % L, A);
  return enc(add(mul(S, B), [md(-k[0]), k[1], k[2], md(-k[3])])) === sig.slice(0, 64);
}
function json(path) { const s = $.NSString.stringWithContentsOfFileEncodingError(path, $.NSUTF8StringEncoding, null); if (s.isNil()) throw new Error("not UTF-8 text"); return JSON.parse(s.js); }
function manifest(path, layer, platform) {
  const m = json(path), out = [], seen = new Set();
  const keys = ["format", "layer", "version", "platform", "run", "files", "minimum"];
  if (typeof m !== "object" || m === null || Object.keys(m).some((k) => !keys.includes(k))) throw new Error("not a release manifest");
  if (m.format !== "nearbytes/update/0.2") throw new Error("an unknown release format");
  if (m.layer !== layer || m.platform !== platform) throw new Error(`a release for ${m.platform} ${m.layer}, not ${platform} ${layer}`);
  if (typeof m.version !== "string" || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/.test(m.version)) throw new Error("no version");
  if (!Array.isArray(m.files) || m.files.length === 0) throw new Error("no files");
  let runs = false;
  for (const f of m.files) {
    const p = f.path;
    if (typeof p !== "string" || p.split("/").some((c) => c === "" || c === "." || c === ".." || /[\\:\u0000-\u001f]/.test(c)) || ["release.json", "release.sig"].includes(p.split("/")[0])) throw new Error("a file's path is not allowed");
    if (seen.has(p.toLowerCase())) throw new Error("two files at one path");
    seen.add(p.toLowerCase());
    if (!Number.isSafeInteger(f.size) || f.size < 0 || typeof f.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(f.sha256) || typeof f.executable !== "boolean") throw new Error("a file is not described");
    if (p === m.run && f.executable) runs = true;
    out.push(`file ${f.sha256} ${f.size} ${f.executable ? 1 : 0} ${p}`);
  }
  if (!runs) throw new Error("no program to run");
  return [`version ${m.version}`, `run ${m.run}`, ...out].join("\n");
}
function revoked(path, key) {
  const l = json(path);
  if (l === null || l.format !== "nearbytes/update/0.3/revoked" || !Array.isArray(l.revoked)) throw new Error("not a list of revocations");
  return l.revoked.filter((r) => r && r.key === key && typeof r.signature === "string" && /^[0-9a-f]{128}$/.test(r.signature)).map((r) => r.signature).join("\n");
}
function run(argv) {
  if (argv[0] === "verify") return verify(argv[1], argv[2], argv[3]) ? "valid" : "invalid";
  if (argv[0] === "manifest") return manifest(argv[1], argv[2], argv[3]);
  if (argv[0] === "revoked") return revoked(argv[1], argv[2]);
  throw new Error("unknown check");
}
JS

# The same reading of the manifest and of the list, for Linux, in Python.
cat > "$tmp/check.py" << 'PY'
import json, re, sys
def manifest(path, layer, platform):
    m = json.loads(open(path, "rb").read().decode("utf-8"))
    if not isinstance(m, dict) or set(m) - {"format", "layer", "version", "platform", "run", "files", "minimum"}:
        sys.exit("not a release manifest")
    if m.get("format") != "nearbytes/update/0.2":
        sys.exit("an unknown release format")
    if m.get("layer") != layer or m.get("platform") != platform:
        sys.exit(f"a release for {m.get('platform')} {m.get('layer')}, not {platform} {layer}")
    if not isinstance(m.get("version"), str) or not re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?", m["version"]):
        sys.exit("no version")
    files = m.get("files")
    if not isinstance(files, list) or not files:
        sys.exit("no files")
    out, seen, runs = [f"version {m['version']}", f"run {m.get('run')}"], set(), False
    for f in files:
        p = f.get("path") if isinstance(f, dict) else None
        if not isinstance(p, str) or any(c in ("", ".", "..") or re.search(r"[\\:\x00-\x1f]", c) for c in p.split("/")) \
                or p.split("/")[0] in ("release.json", "release.sig"):
            sys.exit("a file's path is not allowed")
        if p.lower() in seen:
            sys.exit("two files at one path")
        seen.add(p.lower())
        size, sha, exe = f.get("size"), f.get("sha256"), f.get("executable")
        if type(size) is not int or size < 0 or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha) or type(exe) is not bool:
            sys.exit("a file is not described")
        runs = runs or (p == m.get("run") and exe)
        out.append(f"file {sha} {size} {1 if exe else 0} {p}")
    if not runs:
        sys.exit("no program to run")
    print("\n".join(out))
def revoked(path, key):
    l = json.loads(open(path, "rb").read().decode("utf-8"))
    if not isinstance(l, dict) or l.get("format") != "nearbytes/update/0.3/revoked" or not isinstance(l.get("revoked"), list):
        sys.exit("not a list of revocations")
    for r in l["revoked"]:
        if isinstance(r, dict) and r.get("key") == key and isinstance(r.get("signature"), str) and re.fullmatch(r"[0-9a-f]{128}", r["signature"]):
            print(r["signature"])
{"manifest": manifest, "revoked": revoked}[sys.argv[1]](*sys.argv[2:])
PY

# Reads JSON: the manifest (layer, platform) or the list of revocations (key).
readjson() {
  if [ "$os" = macos ]; then osascript -l JavaScript "$tmp/check.js" "$@"; else python3 -I "$tmp/check.py" "$@"; fi
}

# True when the 64 bytes in the file $3 are the release key's signature of label $1, a byte 0, then the file $2.
verified() {
  [ "$(wc -c < "$3" | tr -d ' ')" -eq 64 ] || return 1
  { printf '%s' "$1"; printf '\000'; cat "$2"; } > "$tmp/signed"
  if [ "$os" = macos ]; then
    h=$({ head -c 32 "$3"; hexbytes "$KEY"; cat "$tmp/signed"; } | openssl dgst -sha512 -binary | tohex)
    [ "$(osascript -l JavaScript "$tmp/check.js" verify "$KEY" "$(tohex < "$3")" "$h")" = valid ]
  else
    # The key as a SubjectPublicKeyInfo (RFC 8410): its fixed prefix, then the 32 bytes.
    hexbytes "302a300506032b6570032100$KEY" > "$tmp/key.der"
    openssl pkeyutl -verify -pubin -inkey "$tmp/key.der" -keyform DER -rawin -in "$tmp/signed" -sigfile "$3" > /dev/null 2>&1
  fi
}

fetch() { curl -fsSL --retry 2 "$1" -o "$2"; }

base="$SITE/releases/$platform/core"
say "Nearbytes: fetching the app for $platform from $SITE"

# 1. The release key is not revoked.
if [ -n "$REVOKED_URL" ]; then
  if fetch "$REVOKED_URL" "$tmp/revoked" 2> /dev/null && readjson revoked "$tmp/revoked" "$KEY" > "$tmp/revocations" 2> /dev/null; then
    while read -r s; do
      [ -n "$s" ] || continue
      hexbytes "$s" > "$tmp/revocation.sig"
      hexbytes "$KEY" > "$tmp/key.bin"
      if verified "$LABEL_REVOKE" "$tmp/key.bin" "$tmp/revocation.sig"; then
        stop "the release key is revoked: this release cannot be trusted. Look at $SITE/warnings/"
      fi
    done < "$tmp/revocations"
  else
    say "  (the list of revoked keys could not be read; going on with the signature alone)"
  fi
fi

# 2. The signature, before the manifest is read.
fetch "$base/release.json" "$tmp/release.json" 2> /dev/null || stop "there is no release for $platform on $SITE yet"
fetch "$base/release.sig" "$tmp/release.sig" 2> /dev/null || stop "the release is not signed: refused"
verified "$LABEL_RELEASE" "$tmp/release.json" "$tmp/release.sig" \
  || stop "the release's signature does not verify under the release key: refused"
say "  signature verified (Ed25519, release key ${KEY%"${KEY#????????}"}…)"

# 3. The manifest: format, layer and platform.
readjson manifest "$tmp/release.json" core "$platform" > "$tmp/files" 2> "$tmp/why" \
  || stop "the release is not one this script can install: $(tail -n 1 "$tmp/why")"
version=$(sed -n 's/^version //p' "$tmp/files")
run=$(sed -n 's/^run //p' "$tmp/files")

# 4. Each file, by its length and its SHA-256, into a staging folder.
mkdir "$tmp/app"
grep '^file ' "$tmp/files" > "$tmp/list"
while read -r _ sha size exe path; do
  if [ "$os" = macos ]; then
    case $path in Nearbytes.app/*) ;; *) stop "a file outside the app's bundle: $path" ;; esac
  fi
  fetch "$base/$sha" "$tmp/blob" 2> /dev/null || stop "a file of the release could not be fetched ($sha)"
  [ "$(wc -c < "$tmp/blob" | tr -d ' ')" = "$size" ] || stop "a file is not the size the signed release says: refused ($path)"
  [ "$(sha256 "$tmp/blob")" = "$sha" ] || stop "a file is not the one the signed release names: refused ($path)"
  mkdir -p "$tmp/app/$(dirname "$path")"
  mv "$tmp/blob" "$tmp/app/$path"
  if [ "$exe" = 1 ]; then chmod 755 "$tmp/app/$path"; else chmod 644 "$tmp/app/$path"; fi
done < "$tmp/list"
say "  every file checked against the signed release: version $version"

# Installed: the new copy replaces the old one only once it is whole.
if [ "$os" = macos ]; then
  dest="$HOME/Applications"
  mkdir -p "$dest"
  rm -rf "${dest:?}/Nearbytes.app.new"
  mv "$tmp/app/Nearbytes.app" "$dest/Nearbytes.app.new"
  rm -rf "${dest:?}/Nearbytes.app"
  mv "$dest/Nearbytes.app.new" "$dest/Nearbytes.app"
  say ""
  say "Installed Nearbytes $version in $dest/Nearbytes.app (for you only, no administrator rights)."
  if ! codesign --verify --deep "$dest/Nearbytes.app" 2> /dev/null; then
    say "Note: macOS cannot check this build's own code signature; if it refuses to open it, run this command again later."
  fi
  say "Open it from Applications in your home folder, or: open \"$dest/Nearbytes.app\""
  say "It was fetched by this script, not by a browser, so macOS does not mark it as downloaded and opens it without"
  say "the warning for apps from outside the App Store. If macOS still says it cannot check the app, open System"
  say "Settings, Privacy & Security, and choose Open Anyway for Nearbytes."
  say "To remove it: rm -rf \"$dest/Nearbytes.app\"  (your data stays in ~/Library/Application Support/app.nearbytes.poc)"
else
  data=${XDG_DATA_HOME:-$HOME/.local/share}
  dest="$data/nearbytes/app"
  mkdir -p "$data/nearbytes" "$HOME/.local/bin" "$data/applications"
  rm -rf "${dest:?}.new"
  mv "$tmp/app" "$dest.new"
  rm -rf "${dest:?}"
  mv "$dest.new" "$dest"
  ln -sf "$dest/$run" "$HOME/.local/bin/nearbytes"
  cat > "$data/applications/nearbytes.desktop" << EOF
[Desktop Entry]
Type=Application
Name=Nearbytes
Comment=Files and chat with the people you choose, device to device
Exec="$dest/$run" %u
Terminal=false
Categories=Network;FileTransfer;
MimeType=x-scheme-handler/nearbytes;
EOF
  command -v update-desktop-database > /dev/null && update-desktop-database "$data/applications" 2> /dev/null || true
  command -v xdg-mime > /dev/null && xdg-mime default nearbytes.desktop x-scheme-handler/nearbytes 2> /dev/null || true
  say ""
  say "Installed Nearbytes $version in $dest (for you only, no administrator rights),"
  say "with the command ~/.local/bin/nearbytes and Nearbytes in your applications menu, which also opens nearbytes:// links."
  say "It needs the system's WebKitGTK 4.1 (on Debian and Ubuntu: libwebkit2gtk-4.1-0), which most desktops have."
  say "To remove it: rm -rf \"$dest\" \"$HOME/.local/bin/nearbytes\" \"$data/applications/nearbytes.desktop\""
  say "(your data stays in $data/app.nearbytes.poc)"
fi
