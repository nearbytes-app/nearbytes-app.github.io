# nearbytes-app.github.io

The public site of Nearbytes, a research proof of concept: https://nearbytes-app.github.io

- `index.html`: the page a hub's invite link opens. The invite is in the link's fragment (after `#`), which a browser
  never sends to any server; the page reads it in the browser only, and offers "Open in the app".
- `warnings/`: the page that warns testers outside the app.
- `releases/`: the release files of the desktop app's plain download, `releases/<platform>/<layer>/release.json`,
  `release.sig` and each file named by its SHA-256. Every release is signed; its integrity rests on that signature.

Only public files are here. The pages are published from the app's repository by its `tools/publish-site.sh`.
