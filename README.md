# nearbytes-app.github.io

The public site of Nearbytes, a research proof of concept: https://nearbytes-app.github.io

- `index.html`: the page a hub's invite link opens. The invite is in the link's fragment (after `#`), which a browser
  never sends to any server; the page reads it in the browser only, and offers the hub in this browser (`app/`) or
  "Open in the app".
- `app/`: the Nearbytes app in the browser, the same app as on the desktop and phones, its core built to WebAssembly
  (`app/core/nearbytes_web.wasm`). It keeps its data in the browser's own storage and meets other devices directly
  over WebRTC; the meeting point carries no data.
- `warnings/`: the page that warns testers outside the app.
- `releases/`: the release files of the desktop app's plain download, `releases/<platform>/<layer>/release.json`,
  `release.sig` and each file named by its SHA-256. Every release is signed; its integrity rests on that signature.

Only public files are here. The pages are published from the app's repository by its `tools/publish-site.sh`.
