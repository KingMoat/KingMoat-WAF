# Smoke for the production-hardening features:
#   - new queue/drop metrics on /metrics
#   - per-request warning-log sampling (KINGMOAT_LOG_SAMPLE_PER_SEC)
#   - per-site publish API + error isolation
#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http | Out-Null
$repo = Split-Path -Parent $PSScriptRoot
$WorkDir = Join-Path $env:TEMP ("km_hardening_smoke_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$DataPort = 19081
$ConsolePort = 19082
$UpstreamPort = 19090
$script:passed = @()
$script:failed = @()

function Check($name, $ok, $detail) {
    if ($ok) {
        $script:passed += $name
        Write-Host ("PASS  " + $name)
    } else {
        $script:failed += $name
        Write-Host ("FAIL  {0} :: {1}" -f $name, $detail) -ForegroundColor Red
    }
}

function HttpGet($client, $url, $hostHeader) {
    $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $url)
    if ($hostHeader) { $req.Headers.Host = $hostHeader }
    $resp = $client.SendAsync($req).GetAwaiter().GetResult()
    $code = [int]$resp.StatusCode
    $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $resp.Dispose()
    New-Object psobject -Property @{ Code = $code; Body = $body }
}

function HttpPost($client, $url, $json) {
    $content = New-Object System.Net.Http.StringContent($json, [System.Text.Encoding]::UTF8, 'application/json')
    $resp = $client.PostAsync($url, $content).GetAwaiter().GetResult()
    $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    New-Object psobject -Property @{ Code = [int]$resp.StatusCode; Body = $body }
}

$procs = @()
$handler = New-Object System.Net.Http.HttpClientHandler
$handler.UseCookies = $false
$client = New-Object System.Net.Http.HttpClient($handler)
$client.Timeout = [TimeSpan]::FromSeconds(15)
try {
    New-Item -ItemType Directory -Force $WorkDir | Out-Null
    $seed = @"
{
  "listen_http": ":$DataPort",
  "audit_log_dir": "logs",
  "log_shipper": {"type": "syslog", "url": "udp://127.0.0.1:51400", "index": "kingmoat"},
  "access_log": {"enabled": true, "type": "syslog", "url": "udp://127.0.0.1:51400", "index": "kingmoat_access"},
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

    Push-Location $repo
    $go = "$env:USERPROFILE\go-sdk\go\bin\go.exe"
    & $go build -tags no_fs_access -o (Join-Path $WorkDir 'kingmoat.exe') ./cmd/kingmoat
    $buildOk = ($LASTEXITCODE -eq 0)
    Pop-Location
    Check 'build kingmoat.exe' $buildOk ("go build exit " + $LASTEXITCODE)
    if (-not $buildOk) { throw 'build failed' }

    $uv = (Get-Command uv).Source
    $up = Start-Process -FilePath $uv `
        -ArgumentList @('run', '--no-project', 'python', '-m', 'http.server', "$UpstreamPort", '--bind', '127.0.0.1') `
        -WorkingDirectory $WorkDir -PassThru -WindowStyle Hidden
    $procs += $up

    $kmLog = Join-Path $WorkDir 'kingmoat.out.log'
    $env:KINGMOAT_LOG_SAMPLE_PER_SEC = "2"
    $km = Start-Process -FilePath (Join-Path $WorkDir 'kingmoat.exe') `
        -ArgumentList @('-config', 'seed.json', '-console-addr', "127.0.0.1:$ConsolePort", '-console-db', 'hardening.db') `
        -WorkingDirectory $WorkDir -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $kmLog -RedirectStandardError (Join-Path $WorkDir 'kingmoat.err.log')
    $procs += $km

    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        try { if ((HttpGet $client "http://127.0.0.1:$ConsolePort/api/status" $null).Code -eq 200) { $ready = $true; break } } catch { }
        Start-Sleep -Milliseconds 500
    }
    Check 'console ready' $ready 'console not ready'
    if (-not $ready) { throw 'console not ready' }
    $dataReady = $false
    for ($i = 0; $i -lt 40; $i++) {
        try { if ((HttpGet $client "http://127.0.0.1:$DataPort/?id=1" 'a.local').Code -eq 200) { $dataReady = $true; break } } catch { }
        Start-Sleep -Milliseconds 500
    }
    Check 'data plane ready' $dataReady 'no 200'

    # 1. prometheus /metrics removed; host resource monitoring exposed
    $m = HttpGet $client "http://127.0.0.1:$ConsolePort/metrics" $null
    # /metrics falls through to the WebUI SPA (no metrics payload); assert no
    # prometheus exposition format is served.
    Check 'prometheus /metrics removed (no exposition)' ($m.Body -notmatch 'kingmoat_requests_total|promhttp') 'metrics still exposed'
    $hs = HttpGet $client "http://127.0.0.1:$ConsolePort/api/host/stats" $null
    Check 'host stats exposed (cpu/mem)' ($hs.Code -eq 200 -and $hs.Body -match 'cpu_used_pct' -and $hs.Body -match 'mem_used_pct') ("code " + $hs.Code + " body " + $hs.Body.Substring(0, [Math]::Min(200, $hs.Body.Length)))
    $hsObj = $hs.Body | ConvertFrom-Json
    Check 'host stats uptime/goroutines present' ($hsObj.uptime_sec -ge 0 -and $hsObj.goroutines -gt 0) 'missing fields'

    # 2. warning-log sampling: 30 SQLi attempts, sampled "request blocked" lines
    for ($i = 0; $i -lt 30; $i++) {
        $null = HttpGet $client ("http://127.0.0.1:$DataPort/?id=1%20UNION%20SELECT%20password%20FROM%20users&x=$i") 'a.local'
    }
    Start-Sleep -Milliseconds 800
    $blockedLines = 0
    if (Test-Path $kmLog) {
        $blockedLines = (Select-String -Path $kmLog -Pattern '"msg":"request blocked"' | Measure-Object).Count
    }
    Check ("sampling: 30 blocks logged <=6 lines (got $blockedLines)") ($blockedLines -gt 0 -and $blockedLines -le 6) 'sampler not throttling or totally silent'

    # 3. per-site publish: retarget a.local upstream (still alive port, different path syntax)
    $siteJson = '{"domains":["a.local"],"mode":"intercept","waf":{"enabled":true},"tls_profile":"strong","upstream":{"nodes":[{"address":"127.0.0.1:' + $UpstreamPort + '"}]}}'
    $pub = HttpPost $client "http://127.0.0.1:$ConsolePort/api/config/site/publish" ('{"domain":"a.local","note":"smoke site publish","site":' + $siteJson + '}')
    Check 'site publish (rev 2)' ($pub.Code -eq 200 -and $pub.Body -match '"revision":2') ("code " + $pub.Code + " body " + $pub.Body)
    $cfg = HttpGet $client "http://127.0.0.1:$ConsolePort/api/config" $null
    Check 'site publish applied (tls_profile=strong)' ($cfg.Body -match '"tls_profile":"strong"') 'profile not applied'
    $fw = HttpGet $client "http://127.0.0.1:$DataPort/?id=ok" 'a.local'
    Check 'traffic ok after site publish' ($fw.Code -eq 200) ("code " + $fw.Code)

    # 4. error isolation: broken site rejected, next publish unaffected
    $bad = HttpPost $client "http://127.0.0.1:$ConsolePort/api/config/site/publish" '{"domain":"bad.local","site":{"domains":["bad.local"],"upstream":{"nodes":[{"address":""}]}}}'
    Check 'broken site rejected (400)' ($bad.Code -eq 400 -and $bad.Body -match 'sites\[') ("code " + $bad.Code + " body " + $bad.Body)
    $good = HttpPost $client "http://127.0.0.1:$ConsolePort/api/config/site/publish" ('{"domain":"c.local","site":{"domains":["c.local"],"upstream":{"nodes":[{"address":"127.0.0.1:' + $UpstreamPort + '"}]}}}')
    Check 'valid publish after failure (200)' ($good.Code -eq 200) ("code " + $good.Code + " body " + $good.Body)
    $cfg2 = HttpGet $client "http://127.0.0.1:$ConsolePort/api/config" $null
    Check 'config now has 2 sites (bad not merged)' ($cfg2.Body -match '"c.local"' -and -not ($cfg2.Body -match '"bad.local"')) 'isolation broken'

    Check 'process alive after all checks' (-not $km.HasExited) 'kingmoat exited'
}
catch {
    Write-Host ("EXCEPTION: " + $_.Exception.Message) -ForegroundColor Red
    $script:failed += 'exception'
}
finally {
    foreach ($p in $procs) { try { if (-not $p.HasExited) { $p.Kill() } } catch { } }
    $client.Dispose()
    Write-Host ''
    Write-Host ("smoke workdir: " + $WorkDir)
    if ($script:failed.Count -gt 0) {
        Write-Host ("SMOKE FAILED: {0} passed, {1} failed" -f $script:passed.Count, $script:failed.Count) -ForegroundColor Red
        exit 1
    }
    Write-Host ("SMOKE PASSED: all {0} checks ok" -f $script:passed.Count) -ForegroundColor Green
}
