<#
.SYNOPSIS
  OpenMDSign Phase-A recon collector for Windows (the vendor's reference platform).

.DESCRIPTION
  Read-only. Captures everything PROTOCOL.md needs about the official
  "MoldSign Server" localhost daemon while it is running:

    - Install dir, jars, bundled JRE, launcher exe
    - Every 127.0.0.1 listener owned by MoldSign/java + full command line
    - Native-messaging host registration (Chrome / Edge / Firefox) in the registry
    - Trusted localhost/MoldSign certs in the Windows cert store
    - The actual TLS cert served on each localhost port (if https)
    - HTTP probes of each port with a real msign Origin (scheme + CORS behavior)
    - Vendor PKCS#11 modules (.dll) and their CPU architecture
    - Copies of vendor config files (*.properties, *.toml)

  It signs NOTHING and never touches the PIN. The two flows that only the
  browser can produce (a real document-sign and a real login) are captured by
  hand — see 99-MANUAL-STEPS.md, written into the output folder.

  Everything lands in a timestamped folder and is zipped for you to send back.

.PARAMETER InstallDir
  Vendor install root. Auto-detected if omitted (looks under Program Files etc.).

.PARAMETER MsignOrigin
  Origin header used when probing CORS. Default https://msign.gov.md.

.PARAMETER OutDir
  Parent dir for the output folder. Default: current directory.

.EXAMPLE
  # From an ordinary PowerShell window, with the token plugged in and the
  # official MoldSign Server running in the tray:
  powershell -ExecutionPolicy Bypass -File .\recon-windows.ps1

.NOTES
  Run as your normal user (same user that runs the tray app) so process paths
  and command lines are visible. No admin required for the core capture; a few
  fields (other-user processes) simply say "access denied" without admin.
#>

[CmdletBinding()]
param(
    [string]$InstallDir,
    [string]$MsignOrigin = 'https://msign.gov.md',
    [string]$OutDir = '.'
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ---- output folder (no Get-Date dependency issues; use .NET directly) --------
$stamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss')
$root  = Join-Path (Resolve-Path $OutDir) "moldsign-recon-$stamp"
New-Item -ItemType Directory -Force -Path $root | Out-Null
$cfgOut = Join-Path $root '07-config-files'; New-Item -ItemType Directory -Force -Path $cfgOut | Out-Null

$summary = [System.Collections.Generic.List[string]]::new()
function Note($s) { $summary.Add($s); Write-Host $s }
function Section($t) { $summary.Add(''); $summary.Add("## $t"); $summary.Add(''); Write-Host "`n=== $t ===" -ForegroundColor Cyan }

Note "# MoldSign Windows recon  —  $stamp"
Note ("Host: {0}   User: {1}   PS: {2}" -f $env:COMPUTERNAME, $env:USERNAME, $PSVersionTable.PSVersion)

# ============================================================================
Section 'Install directory & bundle inventory'
# ============================================================================
if (-not $InstallDir) {
    $candidates = @(
        (Join-Path $env:ProgramFiles 'STISC\MoldSign'),
        (Join-Path ${env:ProgramFiles(x86)} 'STISC\MoldSign'),
        (Join-Path $env:LOCALAPPDATA 'STISC\MoldSign'),
        (Join-Path $env:ProgramFiles 'CTS\MoldSign'),
        (Join-Path $env:ProgramFiles 'MoldSign')
    ) | Where-Object { $_ -and (Test-Path $_) }
    if (-not $candidates) {
        # brute search two common roots, bounded depth
        $candidates = @('C:\Program Files','C:\Program Files (x86)',$env:LOCALAPPDATA) |
            Where-Object { $_ -and (Test-Path $_) } |
            ForEach-Object { Get-ChildItem -Path $_ -Filter 'MoldSign*' -Directory -Recurse -Depth 3 -ErrorAction SilentlyContinue } |
            Select-Object -ExpandProperty FullName
    }
    $InstallDir = $candidates | Select-Object -First 1
}
if ($InstallDir -and (Test-Path $InstallDir)) {
    Note "Install dir: $InstallDir"
    Get-ChildItem -Path $InstallDir -Recurse -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTime |
        Export-Csv -NoTypeInformation -Path (Join-Path $root '00-bundle-inventory.csv')
    $jars = Get-ChildItem -Path $InstallDir -Recurse -Filter *.jar -ErrorAction SilentlyContinue
    Note ("Jars: {0}   (server/network jars of interest:)" -f $jars.Count)
    $jars | Where-Object { $_.Name -match 'Server|Network|Card|jersey|grizzly' } |
        ForEach-Object { Note ("  {0}" -f $_.Name) }
} else {
    Note "!! Install dir not found. Re-run with -InstallDir <path>. Continuing with runtime capture."
}

# ============================================================================
Section 'Localhost listeners + owning process + command line  (THE crux)'
# ============================================================================
$portFile = Join-Path $root '01-listeners.txt'
$listeners = @()
try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { $_.LocalAddress -in @('127.0.0.1','::1','0.0.0.0','::') }
} catch {
    # PS 5.1 without NetTCPIP: fall back to netstat parsing
    $listeners = netstat -ano | Select-String 'LISTENING' | ForEach-Object {
        $c = ($_ -replace '\s+',' ').Trim().Split(' ')
        [pscustomobject]@{ LocalAddress=($c[1] -replace ':\d+$',''); LocalPort=[int]($c[1] -replace '^.*:',''); OwningProcess=[int]$c[-1] }
    }
}
$rows = foreach ($l in $listeners) {
    $p = $null; $cmd = ''
    try { $p = Get-Process -Id $l.OwningProcess -ErrorAction Stop } catch {}
    try { $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$($l.OwningProcess)" -ErrorAction Stop).CommandLine } catch {}
    [pscustomobject]@{
        Address = $l.LocalAddress; Port = $l.LocalPort; PID = $l.OwningProcess
        Process = if ($p) { $p.ProcessName } else { '?' }
        Path    = if ($p) { try { $p.Path } catch { '' } } else { '' }
        CommandLine = $cmd
    }
}
$rows | Format-List | Out-File -Encoding utf8 $portFile
$rows | Export-Csv -NoTypeInformation -Path (Join-Path $root '01-listeners.csv')

# The MoldSign server is a Java process; highlight likely candidates.
$moldPorts = $rows | Where-Object {
    $_.Process -match 'java|MoldSign|jre' -or $_.CommandLine -match 'MoldSign|ClientCardServer|grizzly'
}
if ($moldPorts) {
    Note "Likely MoldSign listener(s):"
    $moldPorts | ForEach-Object { Note ("  {0}:{1}  pid={2}  {3}" -f $_.Address,$_.Port,$_.PID,$_.Process) }
    $moldPorts | ForEach-Object { if ($_.CommandLine) { Note ("    cmd: {0}" -f $_.CommandLine) } }
} else {
    Note "!! No java/MoldSign listener found. Is the tray app running with the token in?"
    Note "   Probing ALL loopback listeners below instead."
    $moldPorts = $rows | Where-Object { $_.Address -in @('127.0.0.1','::1') }
}

# ============================================================================
Section 'Native-messaging host registration (registry)'
# ============================================================================
$nmFile = Join-Path $root '03-native-messaging.txt'
$nmKeys = @(
    'HKCU:\Software\Google\Chrome\NativeMessagingHosts',
    'HKLM:\Software\Google\Chrome\NativeMessagingHosts',
    'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts',
    'HKLM:\Software\Microsoft\Edge\NativeMessagingHosts',
    'HKCU:\Software\Mozilla\NativeMessagingHosts',
    'HKLM:\Software\Mozilla\NativeMessagingHosts'
)
$nmFound = $false
"Native-messaging hosts (if any manifest path is listed, open that JSON)" | Out-File -Encoding utf8 $nmFile
foreach ($k in $nmKeys) {
    if (Test-Path $k) {
        Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
            $manifest = (Get-ItemProperty $_.PSPath).'(default)'
            "$($_.PSChildName)  ->  $manifest" | Out-File -Append -Encoding utf8 $nmFile
            if ($manifest -match 'MoldSign|STISC') { $nmFound = $true }
            if ($manifest -and (Test-Path $manifest)) {
                Copy-Item $manifest -Destination (Join-Path $root ("03-nm-" + (Split-Path $manifest -Leaf))) -ErrorAction SilentlyContinue
            }
        }
    }
}
if ($nmFound) {
    Note "Native-messaging host referencing MoldSign FOUND (see 03-*). Transport may be an extension."
} else {
    Note "No MoldSign native-messaging host registered -> transport is almost certainly localhost HTTP/WS, not an extension."
}

# ============================================================================
Section 'Trusted localhost / MoldSign certs in the Windows cert store'
# ============================================================================
$certFile = Join-Path $root '04-certstore.txt'
$stores = @('Cert:\CurrentUser\Root','Cert:\LocalMachine\Root','Cert:\CurrentUser\My','Cert:\LocalMachine\CA')
$hits = foreach ($s in $stores) {
    Get-ChildItem $s -ErrorAction SilentlyContinue | Where-Object {
        $_.Subject -match '127\.0\.0\.1|localhost|MoldSign|STISC' -or $_.Issuer -match 'MoldSign|STISC'
    } | Select-Object @{n='Store';e={$s}}, Subject, Issuer, Thumbprint, NotAfter,
        @{n='SAN';e={ ($_.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Subject Alternative Name'} | ForEach-Object {$_.Format($false)}) -join '; ' }}
}
if ($hits) { $hits | Format-List | Out-File -Encoding utf8 $certFile; Note "Local/MoldSign trust anchors found (see 04-certstore.txt):"; $hits | ForEach-Object { Note ("  [{0}] {1}" -f $_.Store,$_.Subject) } }
else { 'No localhost/MoldSign cert found in Root/CA/My stores.' | Out-File -Encoding utf8 $certFile; Note "No localhost/MoldSign cert in trust stores -> daemon likely serves plain http on loopback (confirm via probe below)." }

# ============================================================================
Section 'Live probe of each localhost port (scheme detection + CORS + TLS cert)'
# ============================================================================
# TLS-bypass for self-signed loopback certs, PS 5.1 and 7+.
try {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class OMS_TrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate c, WebRequest r, int p) { return true; }
}
"@ -ErrorAction SilentlyContinue
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object OMS_TrustAll
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12,Tls11,Tls'
    }
} catch {}

function Get-ServedCert([int]$Port) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect('127.0.0.1',$Port)
        $cb  = [System.Net.Security.RemoteCertificateValidationCallback]{ param($a,$b,$c,$d) $true }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(),$false,$cb)
        $ssl.AuthenticateAsClient('127.0.0.1')
        $c2  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $out = "TLS: yes  Subject=$($c2.Subject)  Issuer=$($c2.Issuer)  Thumb=$($c2.Thumbprint)  NotAfter=$($c2.NotAfter)"
        $ssl.Dispose(); $tcp.Close(); return $out
    } catch { return "TLS: no / handshake failed ($($_.Exception.Message))" }
}

$probeFile = Join-Path $root '06-endpoint-probes.txt'
$probePaths = @('/','/status','/version','/info','/api','/rest','/health','/getversion','/sign','/auth')  # GET-only guesses; harmless
$targetPorts = ($moldPorts | Select-Object -ExpandProperty Port -Unique)
"Endpoint probes  (Origin: $MsignOrigin)`n" | Out-File -Encoding utf8 $probeFile
foreach ($port in $targetPorts) {
    "===== port $port =====" | Out-File -Append -Encoding utf8 $probeFile
    (Get-ServedCert $port)   | Tee-Object -FilePath $probeFile -Append | Out-Null
    foreach ($scheme in @('http','https')) {
        foreach ($path in $probePaths) {
            $url = "${scheme}://127.0.0.1:$port$path"
            foreach ($method in @('GET','OPTIONS')) {
                try {
                    $params = @{ Uri=$url; Method=$method; TimeoutSec=5; UseBasicParsing=$true
                                Headers=@{ Origin=$MsignOrigin
                                           'Access-Control-Request-Method'='POST'
                                           'Access-Control-Request-Headers'='content-type' } }
                    if ($PSVersionTable.PSVersion.Major -ge 6) { $params['SkipCertificateCheck']=$true }
                    $r = Invoke-WebRequest @params
                    $acao = $r.Headers['Access-Control-Allow-Origin']
                    $srv  = $r.Headers['Server']
                    $line = "{0,-7} {1,-40} -> {2}  Server='{3}'  ACAO='{4}'" -f $method,$url,$r.StatusCode,$srv,$acao
                    $line | Out-File -Append -Encoding utf8 $probeFile
                    if ($path -eq '/' -and $method -eq 'GET' -and $r.Content) {
                        ("    body[0..300]: " + ($r.Content.Substring(0,[Math]::Min(300,$r.Content.Length)) -replace '\s+',' ')) |
                            Out-File -Append -Encoding utf8 $probeFile
                    }
                } catch {
                    $code = $null
                    try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
                    if ($code) { "{0,-7} {1,-40} -> HTTP {2}" -f $method,$url,$code | Out-File -Append -Encoding utf8 $probeFile }
                    # connection refused for the wrong scheme is expected noise; skip logging it
                }
            }
        }
    }
    # A deliberately-wrong Origin to reveal allowlist enforcement:
    try {
        $bad = @{ Uri="http://127.0.0.1:$port/"; Method='GET'; TimeoutSec=5; UseBasicParsing=$true; Headers=@{ Origin='https://evil.example' } }
        if ($PSVersionTable.PSVersion.Major -ge 6) { $bad['SkipCertificateCheck']=$true }
        $rb = Invoke-WebRequest @bad
        "EVIL-ORIGIN  http://127.0.0.1:$port/  -> $($rb.StatusCode)  ACAO='$($rb.Headers['Access-Control-Allow-Origin'])'" | Out-File -Append -Encoding utf8 $probeFile
    } catch {}
}
Note "Endpoint probes written to 06-endpoint-probes.txt (look for Server='Grizzly...', the ACAO header, and TLS yes/no)."

# ============================================================================
Section 'Vendor PKCS#11 modules (.dll) and CPU architecture'
# ============================================================================
$modFile = Join-Path $root '08-modules.txt'
function Get-PEArch([string]$Path) {
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        $br = New-Object System.IO.BinaryReader($fs)
        $fs.Position = 0x3C; $peOff = $br.ReadInt32()
        $fs.Position = $peOff; $sig = $br.ReadUInt32()          # 'PE\0\0'
        $machine = $br.ReadUInt16()
        $br.Close(); $fs.Close()
        switch ($machine) { 0x8664 {'x64'} 0x14c {'x86'} 0xAA64 {'arm64'} default { "0x{0:X}" -f $machine } }
    } catch { "unreadable ($($_.Exception.Message))" }
}
"PKCS#11 / token DLLs found (arch must match the openmdsignd build):`n" | Out-File -Encoding utf8 $modFile
$dllNames = 'castle|bit4|acos5|etoken|idprime|pkcs11|cardos|pki'
$dlls = @()
if ($InstallDir -and (Test-Path $InstallDir)) {
    $dlls += Get-ChildItem -Path $InstallDir -Recurse -Filter *.dll -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $dllNames }
}
# Also common vendor middleware install locations, in case drivers live outside the app:
foreach ($d in @("$env:SystemRoot\System32","$env:SystemRoot\SysWOW64","$env:ProgramFiles","${env:ProgramFiles(x86)}")) {
    if (Test-Path $d) { $dlls += Get-ChildItem -Path $d -Filter *.dll -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $dllNames } }
}
$dlls = $dlls | Sort-Object FullName -Unique
if ($dlls) {
    foreach ($m in $dlls) { "{0,-6}  {1}" -f (Get-PEArch $m.FullName), $m.FullName | Tee-Object -FilePath $modFile -Append }
    Note ("Found {0} candidate token DLL(s); see 08-modules.txt for arch." -f $dlls.Count)
} else {
    'No token DLLs auto-located; check the token vendor middleware install dir.' | Out-File -Append -Encoding utf8 $modFile
    Note "No token DLLs auto-located (check vendor middleware dir)."
}

# ============================================================================
Section 'Copy vendor config files'
# ============================================================================
if ($InstallDir -and (Test-Path $InstallDir)) {
    Get-ChildItem -Path $InstallDir -Recurse -Include *.properties,*.toml,*.cfg,*.conf,*.ini -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\jre\\' } |
        ForEach-Object {
            $dest = Join-Path $cfgOut ($_.FullName.Substring($InstallDir.Length).TrimStart('\') -replace '[\\/]','__')
            Copy-Item $_.FullName -Destination $dest -ErrorAction SilentlyContinue
        }
    Note ("Config files copied to 07-config-files\ (look for a port / listen setting).")
}

# ============================================================================
Section 'Manual capture steps (the two browser-driven flows)'
# ============================================================================
$manual = @"
# 99 - MANUAL STEPS  (do these while the token is plugged in)

The automated capture above cannot produce a real *sign* or *login* payload —
those only exist when the government page drives the daemon. Capture both by hand.

## A. Record both flows as HAR (network capture)
1. Open Microsoft Edge or Chrome. Press F12 -> Network tab.
2. Tick **Preserve log**. Leave the filter empty (we want ALL requests,
   including the 127.0.0.1 ones the page makes to the daemon).
3. Go to https://msign.gov.md (or a service that uses MSign login).

### A1. SIGN flow
4. Perform a real document signature end to end (use a throwaway 1-page PDF and
   a throwaway .txt if the page lets you pick a file).
5. In the Network tab, right-click -> **Save all as HAR with content** ->
   save as  sign.har  into THIS folder:
       $root
6. Note which 127.0.0.1:PORT requests appeared and in what order (the discovery
   handshake, then the sign request, then the result POST back to the server).

### A2. LOGIN / AUTH flow
7. Clear the network log, start a fresh MSign **login** (authentication).
8. Save all as HAR -> login.har into the same folder.

The auth flow is challenge-response: the portal hands a nonce, the daemon signs
it with the token, and returns signature + certificate. Capture it separately
from signing — the schemas differ.

## B. If DevTools hides the 127.0.0.1 request/response bodies
Some pages talk to the daemon in a way DevTools won't fully show. If so, put a
loopback proxy in front:
  - Fiddler Classic: Tools -> Options -> HTTPS: decrypt; Connections: allow
    remote. Then capture. Export sessions as .saz into this folder.
  - or mitmproxy:  mitmweb --mode local  (or a reverse proxy on the daemon port).

## C. What to write down alongside the HARs (paste into the report)
  - Exact daemon URL(s) the page hit: scheme + 127.0.0.1 + PORT + path.
  - Did the page try a RANGE of ports (discovery scan) or one fixed port?
  - The Origin header the page sent to the daemon, and the daemon's
    Access-Control-Allow-Origin response.
  - The request/response body for (a) sign and (b) auth — JSON? XML? field names
    (document/hash, format, certificate, sessionId, nonce/challenge)?
  - How the result is handed back to the page and posted onward (ReturnUrl /
    RelayState).
"@
$manual | Out-File -Encoding utf8 (Join-Path $root '99-MANUAL-STEPS.md')
Note "Wrote 99-MANUAL-STEPS.md — do the SIGN and LOGIN HAR captures next."

# ---- write summary + zip ----------------------------------------------------
$summary -join "`r`n" | Out-File -Encoding utf8 (Join-Path $root '00-summary.md')
$zip = "$root.zip"
try { Compress-Archive -Path $root -DestinationPath $zip -Force; Note "`nZipped -> $zip" } catch { Note "Zip failed: $($_.Exception.Message)" }

Write-Host "`nDONE. Automated artifacts in:`n  $root" -ForegroundColor Green
Write-Host "Now follow 99-MANUAL-STEPS.md to add sign.har + login.har, then re-zip and send back." -ForegroundColor Yellow
