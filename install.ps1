# Installs the Nearbytes app on Windows, for this person only, with no administrator rights:
#
#   irm https://nearbytes-app.github.io/install.ps1 | iex
#
# It fetches the app's release for this computer from the public site (update 0.4 section 6.2:
# releases/<platform>/core/, release.json, release.sig and each file named by its SHA-256), and checks it as the app's
# own updater does (update 0.4 section 2), before anything is written where the person will run it:
#
#   1. the release key is not revoked: the meeting point's list (section 2.1), a revocation counted only when it verifies;
#   2. release.sig is the Ed25519 signature (RFC 8032, verified strictly: S below the group order, neither the key nor R
#      of small order) of "nearbytes/update/0.2/release", a byte 0, then release.json's bytes exactly as fetched, under
#      the release key below, the same public key the apps ship (crates/nearbytes-update/src/lib.rs, RELEASE_KEY);
#   3. the manifest's format, layer ("core") and platform are this computer's;
#   4. each file's length and SHA-256 are the manifest's.
#
# The first failure stops it and nothing is installed. Windows has no Ed25519 of its own: the signature is checked by
# the short verifier below (RFC 8032 section 5.1.7), compiled by PowerShell, over the system's own SHA-512 and big
# integers (.NET's System.Security.Cryptography and System.Numerics). HTTPS is not trusted for integrity: only the
# signature is. This file is ASCII only, so that any PowerShell reads it alike.
#
# Where it installs: %LOCALAPPDATA%\Programs\Nearbytes, a shortcut in the Start menu, and nearbytes:// links opened by
# it (in this person's own registry, HKCU). The app's data is not touched.
#
# For tests only: NEARBYTES_SITE names another site, NEARBYTES_INSTALL_TEST_KEY another release key (hexadecimal),
# NEARBYTES_REVOKED_URL another list of revocations (empty: none is read), NEARBYTES_INSTALL_TEST_ROOT a folder that
# stands for both %LOCALAPPDATA% and the Start menu, with nothing written to the registry.
& {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Site = if ($env:NEARBYTES_SITE) { $env:NEARBYTES_SITE } else { 'https://nearbytes-app.github.io' }
$Key = if ($env:NEARBYTES_INSTALL_TEST_KEY) { $env:NEARBYTES_INSTALL_TEST_KEY } else { '027fd97767893fdc0bcbaedf04c3a37445147c4262fd6c72ed6633af0c1191a4' }
$RevokedUrl = if (Test-Path env:NEARBYTES_REVOKED_URL) { $env:NEARBYTES_REVOKED_URL } else { 'https://nearbytes.make-become.workers.dev/release/revoked' }
$TestRoot = $env:NEARBYTES_INSTALL_TEST_ROOT

$verifier = @'
using System;
using System.Numerics;
using System.Security.Cryptography;
public static class NearbytesEd25519 {
  static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
  static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
  static BigInteger M(BigInteger a) { BigInteger r = a % P; return r.Sign < 0 ? r + P : r; }
  static BigInteger Inv(BigInteger a) { return BigInteger.ModPow(M(a), P - 2, P); }
  static readonly BigInteger D = M(-121665 * Inv(121666));
  static readonly BigInteger I = BigInteger.ModPow(2, (P - 1) / 4, P);
  static BigInteger Le(byte[] b, int off, int len) { byte[] t = new byte[len + 1]; Array.Copy(b, off, t, 0, len); return new BigInteger(t); }
  static BigInteger[] Add(BigInteger[] p, BigInteger[] q) {
    BigInteger a = M((p[1] - p[0]) * (q[1] - q[0])), b = M((p[1] + p[0]) * (q[1] + q[0]));
    BigInteger c = M(2 * D * p[3] * q[3]), d = M(2 * p[2] * q[2]);
    BigInteger e = b - a, f = d - c, g = d + c, h = b + a;
    return new BigInteger[] { M(e * f), M(g * h), M(f * g), M(e * h) };
  }
  static BigInteger[] Mul(BigInteger n, BigInteger[] p) {
    BigInteger[] r = new BigInteger[] { 0, 1, 1, 0 }, q = p;
    while (n.Sign > 0) { if (!n.IsEven) r = Add(r, q); q = Add(q, q); n >>= 1; }
    return r;
  }
  static byte[] Enc(BigInteger[] p) {
    BigInteger z = Inv(p[2]), x = M(p[0] * z), y = M(p[1] * z);
    byte[] o = new byte[32], yb = y.ToByteArray();
    Array.Copy(yb, 0, o, 0, Math.Min(yb.Length, 32));
    if (!x.IsEven) o[31] |= 0x80;
    return o;
  }
  static BigInteger[] Dec(byte[] s, int off) {
    byte[] b = new byte[32]; Array.Copy(s, off, b, 0, 32);
    int sign = b[31] >> 7; b[31] &= 0x7f;
    BigInteger y = Le(b, 0, 32);
    if (y >= P) return null;
    BigInteger y2 = M(y * y), x2 = M((y2 - 1) * Inv(D * y2 + 1));
    if (x2.IsZero) return sign == 1 ? null : new BigInteger[] { 0, y, 1, 0 };
    BigInteger x = BigInteger.ModPow(x2, (P + 3) / 8, P);
    if (!M(x * x - x2).IsZero) x = M(x * I);
    if (!M(x * x - x2).IsZero) return null;
    if ((x.IsEven ? 0 : 1) != sign) x = P - x;
    return new BigInteger[] { x, y, 1, M(x * y) };
  }
  static bool Same(byte[] a, byte[] b, int boff) { for (int i = 0; i < 32; i++) if (a[i] != b[boff + i]) return false; return true; }
  static bool Small(BigInteger[] p) { byte[] e = Enc(Mul(8, p)); byte[] id = new byte[32]; id[0] = 1; return Same(e, id, 0); }
  static readonly BigInteger[] B = Dec(Base(), 0);
  static byte[] Base() { byte[] b = new byte[32]; b[0] = 0x58; for (int i = 1; i < 32; i++) b[i] = 0x66; return b; }
  // True when sig is the signature of msg under pub (RFC 8032 section 5.1.7, cofactorless, strict).
  public static bool Verify(byte[] pub, byte[] sig, byte[] msg) {
    if (pub.Length != 32 || sig.Length != 64) return false;
    BigInteger[] A = Dec(pub, 0), R = Dec(sig, 0);
    if (A == null || R == null || Small(A) || Small(R)) return false;
    BigInteger S = Le(sig, 32, 32);
    if (S >= L) return false;
    byte[] all = new byte[64 + msg.Length];
    Array.Copy(sig, 0, all, 0, 32); Array.Copy(pub, 0, all, 32, 32); Array.Copy(msg, 0, all, 64, msg.Length);
    byte[] h; using (SHA512 sha = SHA512.Create()) { h = sha.ComputeHash(all); }
    BigInteger[] k = Mul(Le(h, 0, 64) % L, A);
    BigInteger[] nk = new BigInteger[] { M(-k[0]), k[1], k[2], M(-k[3]) };
    return Same(Enc(Add(Mul(S, B), nk)), sig, 0);
  }
}
'@

function Stop-Install($why) { throw "Nearbytes was not installed: $why" }
function Bytes-Of($hex) {
  if ($hex -notmatch '^([0-9a-f]{2})*$') { Stop-Install 'a key or signature is not hexadecimal' }
  $b = New-Object byte[] ($hex.Length / 2)
  for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($hex.Substring(2 * $i, 2), 16) }
  ,$b
}
function Labelled($label, [byte[]]$message) {
  $l = [Text.Encoding]::ASCII.GetBytes($label)
  $all = New-Object byte[] ($l.Length + 1 + $message.Length)
  [Array]::Copy($l, 0, $all, 0, $l.Length)
  [Array]::Copy($message, 0, $all, $l.Length + 1, $message.Length)
  ,$all
}
function Hex-Of([byte[]]$b) { -join ($b | ForEach-Object { $_.ToString('x2') }) }
$web = New-Object Net.WebClient
function Fetch($url) { ,$web.DownloadData($url) }

try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  if ($Key -notmatch '^[0-9a-f]{64}$') { Stop-Install 'the release key is not 32 bytes in hexadecimal' }
  if (-not ('NearbytesEd25519' -as [type])) {
    if ($PSVersionTable.PSEdition -eq 'Core') { Add-Type -TypeDefinition $verifier }
    else { Add-Type -TypeDefinition $verifier -ReferencedAssemblies System.Numerics }
  }
  $arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'x86_64' } 'ARM64' { 'aarch64' } default { $null } }
  if (-not $arch) { Stop-Install "no build for this processor ($env:PROCESSOR_ARCHITECTURE)" }
  $platform = "windows-$arch"
  $pub = Bytes-Of $Key
  $base = "$Site/releases/$platform/core"
  Write-Host "Nearbytes: fetching the app for $platform from $Site"

  # 1. The release key is not revoked.
  if ($RevokedUrl) {
    $list = $null
    try { $list = [Text.Encoding]::UTF8.GetString((Fetch $RevokedUrl)) | ConvertFrom-Json } catch { $list = $null }
    if ($list -and $list.format -eq 'nearbytes/update/0.3/revoked') {
      foreach ($r in @($list.revoked)) {
        if ($r.key -eq $Key -and "$($r.signature)" -match '^[0-9a-f]{128}$' -and
            [NearbytesEd25519]::Verify($pub, (Bytes-Of $r.signature), (Labelled 'nearbytes/update/0.3/revoke' $pub))) {
          Stop-Install "the release key is revoked: this release cannot be trusted. Look at $Site/warnings/"
        }
      }
    } else { Write-Host '  (the list of revoked keys could not be read; going on with the signature alone)' }
  }

  # 2. The signature, before the manifest is read.
  try { $manifest = Fetch "$base/release.json" } catch { Stop-Install "there is no release for $platform on $Site yet" }
  try { $sig = Fetch "$base/release.sig" } catch { Stop-Install 'the release is not signed: refused' }
  if (-not [NearbytesEd25519]::Verify($pub, $sig, (Labelled 'nearbytes/update/0.2/release' $manifest))) {
    Stop-Install "the release's signature does not verify under the release key: refused"
  }
  Write-Host "  signature verified (Ed25519, release key $($Key.Substring(0, 8))...)"

  # 3. The manifest: format, layer and platform.
  $m = [Text.Encoding]::UTF8.GetString($manifest) | ConvertFrom-Json
  $allowed = 'format', 'layer', 'version', 'platform', 'run', 'files', 'minimum'
  if (@($m.PSObject.Properties.Name | Where-Object { $allowed -notcontains $_ }).Count -gt 0) { Stop-Install 'not a release manifest' }
  if ($m.format -ne 'nearbytes/update/0.2') { Stop-Install 'an unknown release format' }
  if ($m.layer -ne 'core' -or $m.platform -ne $platform) { Stop-Install "a release for $($m.platform) $($m.layer), not $platform core" }
  if ("$($m.version)" -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$') { Stop-Install 'no version' }
  $files = @($m.files)
  if ($files.Count -eq 0) { Stop-Install 'no files' }
  $seen = @{}
  $runs = $false
  foreach ($f in $files) {
    $p = $f.path
    if ($p -isnot [string] -or @($p.Split('/') | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' -or $_ -match '[\\:\x00-\x1f<>"|?*]' }).Count -gt 0 -or
        @('release.json', 'release.sig') -contains $p.Split('/')[0]) { Stop-Install "a file's path is not allowed" }
    if ($seen.ContainsKey($p.ToLowerInvariant())) { Stop-Install 'two files at one path' }
    $seen[$p.ToLowerInvariant()] = $true
    if (-not ($f.size -is [int] -or $f.size -is [long]) -or $f.size -lt 0 -or "$($f.sha256)" -notmatch '^[0-9a-f]{64}$' -or $f.executable -isnot [bool]) {
      Stop-Install 'a file is not described'
    }
    if ($p -eq $m.run -and $f.executable) { $runs = $true }
  }
  if (-not $runs) { Stop-Install 'no program to run' }

  # 4. Each file, by its length and its SHA-256, into a staging folder.
  $local = if ($TestRoot) { $TestRoot } else { $env:LOCALAPPDATA }
  $programs = Join-Path $local 'Programs'
  $dest = Join-Path $programs 'Nearbytes'
  $stage = "$dest.new"
  New-Item -ItemType Directory -Force -Path $programs | Out-Null
  if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
  New-Item -ItemType Directory -Path $stage | Out-Null
  $sha = [Security.Cryptography.SHA256]::Create()
  foreach ($f in $files) {
    try { $blob = Fetch "$base/$($f.sha256)" } catch { Remove-Item -Recurse -Force $stage; Stop-Install "a file of the release could not be fetched ($($f.sha256))" }
    if ($blob.Length -ne $f.size) { Remove-Item -Recurse -Force $stage; Stop-Install "a file is not the size the signed release says: refused ($($f.path))" }
    if ((Hex-Of $sha.ComputeHash($blob)) -ne $f.sha256) { Remove-Item -Recurse -Force $stage; Stop-Install "a file is not the one the signed release names: refused ($($f.path))" }
    $to = Join-Path $stage ($f.path -replace '/', '\')
    New-Item -ItemType Directory -Force -Path (Split-Path $to) | Out-Null
    [IO.File]::WriteAllBytes($to, $blob)
  }
  Write-Host "  every file checked against the signed release: version $($m.version)"

  # Installed: the new copy replaces the old one only once it is whole.
  if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
  Move-Item $stage $dest
  $exe = Join-Path $dest ($m.run -replace '/', '\')
  $menu = if ($TestRoot) { Join-Path $TestRoot 'Start Menu' } else { [Environment]::GetFolderPath('Programs') }
  New-Item -ItemType Directory -Force -Path $menu | Out-Null
  $lnk = Join-Path $menu 'Nearbytes.lnk'
  $shell = New-Object -ComObject WScript.Shell
  $s = $shell.CreateShortcut($lnk)
  $s.TargetPath = $exe
  $s.WorkingDirectory = $dest
  $s.Save()
  if (-not $TestRoot) {
    $cls = 'HKCU:\Software\Classes\nearbytes'
    New-Item -Force -Path "$cls\shell\open\command" | Out-Null
    Set-ItemProperty -Path $cls -Name '(default)' -Value 'URL:Nearbytes'
    Set-ItemProperty -Path $cls -Name 'URL Protocol' -Value ''
    Set-ItemProperty -Path "$cls\shell\open\command" -Name '(default)' -Value "`"$exe`" `"%1`""
  }
  Write-Host ''
  Write-Host "Installed Nearbytes $($m.version) in $dest (for you only, no administrator rights),"
  Write-Host 'with Nearbytes in the Start menu, which also opens nearbytes:// links.'
  Write-Host 'It was fetched by this script, not by a browser, so Windows does not mark it as downloaded and opens it without'
  Write-Host 'asking. If Windows still says it protected your PC, choose More info, then Run anyway. Where Smart App Control'
  Write-Host 'is on, Windows refuses every app not signed for Windows, this one too: use Nearbytes in the browser there.'
  Write-Host 'To remove it, in PowerShell:'
  Write-Host "  Remove-Item -Recurse -Force '$dest', '$lnk'; Remove-Item -Recurse -Force HKCU:\Software\Classes\nearbytes"
  Write-Host "(your data stays in $local\app.nearbytes.poc)"
} catch {
  Write-Host $_.Exception.Message -ForegroundColor Red
}
}
