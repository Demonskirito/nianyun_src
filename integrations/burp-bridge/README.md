# Nianyun Burp Bridge

Montoya extension (Burp 2024.7 API) that gives the Nianyun agent the full programmable Burp
surface over a bearer-token HTTP API on `0.0.0.0:8765`.

## Build

```powershell
$jdk = 'C:\Users\29199\.jdks\jbr-17.0.14\bin'
$dir = 'integrations\burp-bridge'
Remove-Item "$dir\target\classes" -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path "$dir\target\classes" -Force | Out-Null
& "$jdk\javac.exe" -encoding UTF-8 -cp "$dir\target\montoya-api.jar" -d "$dir\target\classes" (Get-ChildItem "$dir\src\main\java\local\nianyun\bridge\*.java").FullName
# manifest must stay BOM-free with a trailing blank line, otherwise Burp rejects the jar
```

## Load

Burp → Extensions → Installed → Add → Java → `target/nianyun-burp-bridge.jar`.
The token lives in the extension preference `nianyun.bridge.token` and survives reloads; the
`Nianyun Bridge` tab shows it.

## Endpoints

See [`docs/tool-capability.md`](../../docs/tool-capability.md#full-surface-bridge-v3). Every call
carries `Authorization: Bearer <token>`; actions that target the scanned application also carry the
session host and are rejected when the URL host differs.
