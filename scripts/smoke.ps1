#requires -Version 5.1
<#
KingMoat all-in-one e2e smoke test.

Chain: build -> start upstream + kingmoat (-console-addr) -> forward OK ->
CRS blocks SQLi -> publish rate-limit config via API -> hot reload -> 429 ->
WebUI/status/logs/metrics checks -> cleanup.

Usage:  powershell -File scripts\smoke.ps1
Exit 0 = all checks passed.
#>
param(
    [int]$DataPort = 8080,
    [int]$ConsolePort = 18899,
    [int]$UpstreamPort = 19099,
    [string]$WorkDir = (Join-Path $env:TEMP ("kingmoat-smoke-" + [guid]::NewGuid().ToString("N").Substring(0, 8)))
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http | Out-Null
$repo = Split-Path -Parent $PSScriptRoot
$go = Join-Path $env:USERPROFILE 'go-sdk\go\bin\go.exe'

$script:passed = @()
$script:failed = @()
function Check($name, $ok, $detail) {
    if ($ok) {
        $script:passed += $name
        Write-Host ("PASS  " + $name)
    } else {
        $script:failed += ("{0} :: {1}" -f $name, $detail)
        Write-Host ("FAIL  {0} :: {1}" -f $name, $detail) -ForegroundColor Red
    }
}

function HttpGet($client, $url, $hostHeader) {
    $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $url)
    if ($hostHeader) { $req.Headers.Host = $hostHeader }
    $resp = $client.SendAsync($req).GetAwaiter().GetResult()
    $code = [int]$resp.StatusCode
    $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $headers = @{}
    foreach ($h in $resp.Headers) { $headers[$h.Key] = @($h.Value) }
    foreach ($h in $resp.Content.Headers) { $headers[$h.Key] = @($h.Value) }
    $resp.Dispose()
    New-Object psobject -Property @{ Code = $code; Body = $body; Headers = $headers }
}

function HttpPost($client, $url, $json) {
    $content = New-Object System.Net.Http.StringContent($json, [System.Text.Encoding]::UTF8, 'application/json')
    $resp = $client.PostAsync($url, $content).GetAwaiter().GetResult()
    $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    New-Object psobject -Property @{ Code = [int]$resp.StatusCode; Body = $body }
}

function Wait-Ready($client, $url, $hostHeader, $tries, $delayMs) {
    for ($i = 0; $i -lt $tries; $i++) {
        try {
            $r = HttpGet $client $url $hostHeader
            if ($r.Code -eq 200) { return $true }
        } catch { }
        Start-Sleep -Milliseconds $delayMs
    }
    return $false
}

$procs = @()
$handler = New-Object System.Net.Http.HttpClientHandler
$handler.UseCookies = $false   # keep Set-Cookie headers visible to assertions
$client = New-Object System.Net.Http.HttpClient($handler)
$client.Timeout = [TimeSpan]::FromSeconds(15)
$kmLog = ''
try {
    # 0. workdir + seed config
    New-Item -ItemType Directory -Force $WorkDir | Out-Null
    $seed = @"
{
  "listen_http": ":$DataPort",
  "audit_log_dir": "logs",
  "api_assets": {"enabled": true, "min_hits": 1},
  "sites": [
    {
      "domains": ["a.local"],
      "mode": "intercept",
      "waf": {"enabled": true},
      "upstream": {"nodes": [{"address": "127.0.0.1:$UpstreamPort"}]}
    }
  ]
}
"@
    $seedPath = Join-Path $WorkDir 'seed.json'
    [System.IO.File]::WriteAllText($seedPath, $seed)

    # 1. build
    Push-Location $repo
    & $go build -tags no_fs_access -o (Join-Path $WorkDir 'kingmoat.exe') ./cmd/kingmoat
    $buildOk = ($LASTEXITCODE -eq 0)
    Pop-Location
    Check 'build kingmoat.exe' $buildOk ("go build exit " + $LASTEXITCODE)
    if (-not $buildOk) { throw 'build failed, aborting smoke test' }

    # 2. upstream (python http.server)
    $uv = (Get-Command uv).Source
    $up = Start-Process -FilePath $uv `
        -ArgumentList @('run', '--no-project', 'python', '-m', 'http.server', "$UpstreamPort", '--bind', '127.0.0.1') `
        -WorkingDirectory $WorkDir -PassThru -WindowStyle Hidden
    $procs += $up

    # 3. kingmoat all-in-one
    $kmLog = Join-Path $WorkDir 'kingmoat.out.log'
    $km = Start-Process -FilePath (Join-Path $WorkDir 'kingmoat.exe') `
        -ArgumentList @('-config', 'seed.json', '-console-addr', "127.0.0.1:$ConsolePort", '-console-db', 'smoke.db') `
        -WorkingDirectory $WorkDir -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $kmLog -RedirectStandardError (Join-Path $WorkDir 'kingmoat.err.log')
    $procs += $km

    # 4. readiness
    $consoleReady = Wait-Ready $client "http://127.0.0.1:$ConsolePort/api/status" $null 120 500
    Check 'console api ready' $consoleReady ("console not ready on 127.0.0.1:$ConsolePort")
    if (-not $consoleReady) { throw 'console not ready, aborting' }

    $dataReady = Wait-Ready $client "http://127.0.0.1:$DataPort/?id=1" 'a.local' 60 500
    Check 'data plane ready (forward 200)' $dataReady ('no 200 from data plane; km alive=' + (-not $km.HasExited))
    if (-not $dataReady) { throw 'data plane not ready, aborting' }

    # 5. CRS blocks SQLi
    $sqli = HttpGet $client ("http://127.0.0.1:$DataPort/?id=1%27%20OR%20%271%27%3D%271") 'a.local'
    Check 'CRS blocks SQLi (403)' ($sqli.Code -eq 403) ("got " + $sqli.Code)

    # 6. publish rate-limit config via API -> hot reload -> 429
    $pubJson = '{"note":"smoke-ratelimit","config":{"listen_http":":DPORT","audit_log_dir":"logs","sites":[{"domains":["a.local"],"waf":{"enabled":true},"upstream":{"nodes":[{"address":"127.0.0.1:UPPORT"}]},"security":{"ratelimit":{"requests":1,"window_sec":60,"action":"throttle"}}}]}}'
    $pubJson = $pubJson.Replace('UPPORT', "$UpstreamPort").Replace('DPORT', "$DataPort")
    $pub = HttpPost $client "http://127.0.0.1:$ConsolePort/api/config/publish" $pubJson
    Check 'publish config rev2' ($pub.Code -ge 200 -and $pub.Code -lt 300 -and $pub.Body -match '"revision":2') ("code " + $pub.Code + " body " + $pub.Body)

    $hotApplied = $false
    for ($i = 0; $i -lt 20; $i++) {
        $cur = HttpGet $client "http://127.0.0.1:$ConsolePort/api/config" $null
        if ($cur.Body -match '"revision":2') {
            Start-Sleep -Milliseconds 400   # let the subscribe goroutine swap state
            $hotApplied = $true
            break
        }
        Start-Sleep -Milliseconds 300
    }
    Check 'revision 2 visible' $hotApplied 'revision never became 2'

    $first = HttpGet $client "http://127.0.0.1:$DataPort/?rl=1" 'a.local'
    $second = HttpGet $client "http://127.0.0.1:$DataPort/?rl=2" 'a.local'
    Check 'hot-reloaded ratelimit: 1st ok, 2nd throttled (429)' ($first.Code -eq 200 -and $second.Code -eq 429) ("first " + $first.Code + " second " + $second.Code)

    # 7. WebUI + status + logs + metrics + revisions
    $ui = HttpGet $client "http://127.0.0.1:$ConsolePort/" $null
    Check 'WebUI serves (KingMoat title)' ($ui.Code -eq 200 -and $ui.Body -match 'KingMoat') ("code " + $ui.Code)

    $st = HttpGet $client "http://127.0.0.1:$ConsolePort/api/status" $null
    Check 'api/status version field' ($st.Code -eq 200 -and $st.Body -match '"version"') ("code " + $st.Code)

    $logs = HttpGet $client "http://127.0.0.1:$ConsolePort/api/logs?limit=20" $null
    Check 'api/logs contains blocked event' ($logs.Code -eq 200 -and $logs.Body -match 'blocked') ("code " + $logs.Code)

    $metrics = HttpGet $client "http://127.0.0.1:$ConsolePort/api/host/stats" $null
    Check 'host stats exposed' ($metrics.Code -eq 200 -and $metrics.Body -match 'cpu_used_pct') ("code " + $metrics.Code)

    $revs = HttpGet $client "http://127.0.0.1:$ConsolePort/api/revisions" $null
    Check 'api/revisions history' ($revs.Code -eq 200 -and $revs.Body -match 'smoke-ratelimit') ("code " + $revs.Code)

    # ---- v0.3: semantic layer + slider captcha (published as revision 3) ----
    $pub3 = '{"note":"smoke-v3","config":{"listen_http":":DPORT","audit_log_dir":"logs","sites":[{"domains":["a.local"],"waf":{"enabled":false},"upstream":{"nodes":[{"address":"127.0.0.1:UPPORT"}]},"security":{"semantic":{"enabled":true},"captcha":{"enabled":true,"secret":"smoke-cap-secret","tolerance":8}}}]}}'
    $pub3 = $pub3.Replace('UPPORT', "$UpstreamPort").Replace('DPORT', "$DataPort")
    $pub3resp = HttpPost $client "http://127.0.0.1:$ConsolePort/api/config/publish" $pub3
    Check 'publish config rev3 (v3 features)' ($pub3resp.Code -ge 200 -and $pub3resp.Body -match '"revision":3') ("code " + $pub3resp.Code + " body " + $pub3resp.Body)
    $hot3 = $false
    for ($i = 0; $i -lt 20; $i++) {
        $cur = HttpGet $client "http://127.0.0.1:$ConsolePort/api/config" $null
        if ($cur.Body -match '"revision":3') { Start-Sleep -Milliseconds 400; $hot3 = $true; break }
        Start-Sleep -Milliseconds 300
    }
    Check 'revision 3 hot-applied' $hot3 'revision never became 3'

    # captcha runs before semantic in the pipeline; flow: challenge → verify
    # → pass cookie → then semantic sees the SQLi request.

    # captcha challenge for benign request ("/" exists on the python upstream;
    # "/private" would 404 upstream after the pass cookie grants access)
    $chal = HttpGet $client "http://127.0.0.1:$DataPort/?cap=1" 'a.local'
    $isChallenge = ($chal.Code -eq 200 -and $chal.Body -match 'km-captcha/verify')
    Check 'slider captcha challenge served' $isChallenge ("code " + $chal.Code)

    # extract token + gap, verify at the correct position, replay with cookie
    $tok = $null; $gapX = $null
    if ($isChallenge) {
        if ($chal.Body -match 'token=([0-9a-f]+)\.([0-9a-f]+)\.([0-9a-f]+)') {
            $tok = $Matches[1] + '.' + $Matches[2] + '.' + $Matches[3]
            $gapHex = $Matches[1]
            $gapX = [Convert]::ToInt32($gapHex, 16)
        }
    }
    Check 'captcha token parsed' ($null -ne $tok -and $null -ne $gapX) 'token/gap missing in challenge page'

    $ver = HttpGet $client "http://127.0.0.1:$DataPort/.well-known/km-captcha/verify?token=$tok&x=$gapX&back=/" 'a.local'
    Check 'captcha verify at correct gap' ($ver.Code -eq 200 -and $ver.Body -match '"ok":true') ("code " + $ver.Code + " body " + $ver.Body)
    $sc = $ver.Headers['Set-Cookie']
    $capCookie = $null
    if ($sc) { $capCookie = @($sc)[0] }
    Check 'captcha pass cookie issued' ($null -ne $capCookie -and "$capCookie" -match 'km_captcha') ("set-cookie: $capCookie; keys: " + (($ver.Headers.Keys | Sort-Object) -join ','))

    $val = ''
    if ($capCookie) { $val = "$capCookie".Split(';')[0] }
    $req3 = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, "http://127.0.0.1:$DataPort/?cap=2")
    $req3.Headers.Host = 'a.local'
    if ($val) { $req3.Headers.Add('Cookie', $val) }
    $resp3 = $client.SendAsync($req3).GetAwaiter().GetResult()
    $code3 = [int]$resp3.StatusCode
    $resp3.Dispose()
    Check 'captcha pass cookie grants access' ($code3 -eq 200) ("code " + $code3)

    # semantic blocks SQLi (cookie holder passes captcha, semantic still hits)
    $req4 = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, "http://127.0.0.1:$DataPort/?id=1%27%20or%20%271%27=%271")
    $req4.Headers.Host = 'a.local'
    if ($val) { $req4.Headers.Add('Cookie', $val) }
    $resp4 = $client.SendAsync($req4).GetAwaiter().GetResult()
    $code4 = [int]$resp4.StatusCode
    $rule4 = ''
    if ($resp4.Headers.Contains('X-KingMoat-Rule')) { $rule4 = ($resp4.Headers.GetValues('X-KingMoat-Rule') | Select-Object -First 1) }
    $resp4.Dispose()
    Check 'semantic blocks SQLi (CRS off)' ($code4 -eq 403 -and $rule4 -match 'semantic/sqli') ("code " + $code4 + " rule " + $rule4)

    # ---- v0.4: BOT detect + API assets + AI surface (published as revision 4) ----
    $pub4 = '{"note":"smoke-v4","config":{"listen_http":":DPORT","audit_log_dir":"logs","api_assets":{"enabled":true,"min_hits":2},"sites":[{"domains":["a.local"],"waf":{"enabled":true},"upstream":{"nodes":[{"address":"127.0.0.1:UPPORT"}]},"security":{"bot_detect":{"enabled":true,"actions":{"good":"allow","unknown":"observe","bad":"observe"},"rate_threshold":{"requests":300,"window_sec":60},"good_bot_bypass_challenge":true}}}]}}'
    $pub4 = $pub4.Replace('UPPORT', "$UpstreamPort").Replace('DPORT', "$DataPort")
    $pub4resp = HttpPost $client "http://127.0.0.1:$ConsolePort/api/config/publish" $pub4
    Check 'publish config rev4 (v4 features)' ($pub4resp.Code -ge 200 -and $pub4resp.Body -match '"revision":4') ("code " + $pub4resp.Code)
    $hot4 = $false
    for ($i = 0; $i -lt 20; $i++) {
        $cur = HttpGet $client "http://127.0.0.1:$ConsolePort/api/config" $null
        if ($cur.Body -match '"revision":4') { Start-Sleep -Milliseconds 500; $hot4 = $true; break }
        Start-Sleep -Milliseconds 300
    }
    Check 'revision 4 hot-applied (botdetect active)' $hot4 'revision never became 4'

    # curl UA -> bad bot (observe default: must NOT be blocked, but labeled)
    $badbot = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, "http://127.0.0.1:$DataPort/?bot=1")
    $badbot.Headers.Host = 'a.local'
    $badbot.Headers.TryAddWithoutValidation('User-Agent', 'curl/8.0.1') | Out-Null
    $bb = $client.SendAsync($badbot).GetAwaiter().GetResult()
    $bbCode = [int]$bb.StatusCode
    $bb.Dispose()
    Check 'bad bot observe default: forwarded (200)' ($bbCode -eq 200) ("code " + $bbCode)

    # googlebot UA + good_bot_bypass: JS challenge config is off in rev4, so just verify 200 forward
    $goodbot = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, "http://127.0.0.1:$DataPort/?bot=2")
    $goodbot.Headers.Host = 'a.local'
    $goodbot.Headers.TryAddWithoutValidation('User-Agent', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)') | Out-Null
    $gb = $client.SendAsync($goodbot).GetAwaiter().GetResult()
    $gbCode = [int]$gb.StatusCode
    $gb.Dispose()
    Check 'good bot forwarded (200)' ($gbCode -eq 200) ("code " + $gbCode)

    # asset list endpoint exists (empty or seeded by the requests above)
    $assets = HttpGet $client "http://127.0.0.1:$ConsolePort/api/assets/apis" $null
    Check 'api/assets/apis reachable' ($assets.Code -eq 200 -and $assets.Body -match '"assets"') ("code " + $assets.Code)

    # risk endpoints reachable
    $risks = HttpGet $client "http://127.0.0.1:$ConsolePort/api/risks" $null
    Check 'api/risks reachable (module off returns 404, on returns 200)' ($risks.Code -in @(200, 404)) ("code " + $risks.Code)

    # AI surface: disabled by default -> config reports enabled:false; chat 404
    $aicfg = HttpGet $client "http://127.0.0.1:$ConsolePort/api/ai/config" $null
    Check 'ai config endpoint (disabled by default)' ($aicfg.Code -eq 200 -and $aicfg.Body -match '"enabled":false') ("code " + $aicfg.Code)
    $aichat = HttpPost $client "http://127.0.0.1:$ConsolePort/api/ai/chat" '{"message":"hi"}'
    Check 'ai chat rejected when disabled (404)' ($aichat.Code -eq 404) ("code " + $aichat.Code)

    # stats carries bot_distribution
    $st2 = HttpGet $client "http://127.0.0.1:$ConsolePort/api/stats" $null
    Check 'api/stats bot_distribution field' ($st2.Code -eq 200 -and $st2.Body -match 'bot_distribution') ("code " + $st2.Code)
} finally {
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    $client.Dispose()
    if ($script:failed.Count -gt 0 -and $kmLog -and (Test-Path $kmLog)) {
        Write-Host '--- kingmoat.log tail ---' -ForegroundColor Yellow
        Get-Content $kmLog -Tail 30 | ForEach-Object { Write-Host $_ }
    }
    Write-Host ("smoke workdir: " + $WorkDir)
}

Write-Host ''
if ($script:failed.Count -gt 0) {
    Write-Host ("SMOKE FAILED: {0} passed, {1} failed" -f $script:passed.Count, $script:failed.Count) -ForegroundColor Red
    exit 1
}
Write-Host ("SMOKE PASSED: all {0} checks ok" -f $script:passed.Count) -ForegroundColor Green
exit 0
