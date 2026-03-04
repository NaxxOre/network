$ErrorActionPreference = 'Stop'

function Write-Step($message) {
    Write-Host "`n=== $message ===" -ForegroundColor Cyan
}

function Assert-Equal($actual, $expected, $label) {
    if ($actual -ne $expected) {
        throw "$label failed. Expected: $expected, Actual: $actual"
    }
    Write-Host "PASS: $label" -ForegroundColor Green
}

function Invoke-DemoRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [hashtable]$Headers,
        [string]$Body,
        [string]$ContentType = 'text/plain'
    )

    try {
        $params = @{
            Method     = $Method
            Uri        = $Uri
            TimeoutSec = 20
            UseBasicParsing = $true
        }
        if ($Headers) { $params.Headers = $Headers }
        if ($PSBoundParameters.ContainsKey('Body')) {
            $params.Body = $Body
            $params.ContentType = $ContentType
        }

        $resp = Invoke-WebRequest @params
        return [pscustomobject]@{
            StatusCode = [int]$resp.StatusCode
            Content    = $resp.Content
        }
    }
    catch {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
            $stream = $response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $content = $reader.ReadToEnd()
            $reader.Dispose()
            return [pscustomobject]@{
                StatusCode = [int]$response.StatusCode
                Content    = $content
            }
        }
        throw
    }
}

function Wait-HttpReady {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [int]$TimeoutSec = 120,
        [int]$IntervalSec = 3
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-RestMethod -Uri $Uri -Method Get -TimeoutSec 10 -UseBasicParsing | Out-Null
            return $true
        }
        catch {
            Start-Sleep -Seconds $IntervalSec
        }
    }

    return $false
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

try {
    Set-Location -Path $PSScriptRoot

    Write-Step "1) Checking Docker availability"
    docker info | Out-Null
    Write-Host "PASS: Docker daemon reachable" -ForegroundColor Green

    Write-Step "2) Starting services"
    docker compose up --build -d
    docker compose ps

    Write-Step "3) Waiting for core endpoints"
    if (-not (Wait-HttpReady -Uri 'http://localhost:8001/docs' -TimeoutSec 90)) {
        throw 'Resource server is not reachable at http://localhost:8001/docs'
    }
    if (-not (Wait-HttpReady -Uri 'http://localhost:8000/docs' -TimeoutSec 90)) {
        throw 'Guard server is not reachable at http://localhost:8000/docs'
    }
    if (-not (Wait-HttpReady -Uri 'http://localhost:9200' -TimeoutSec 120)) {
        throw 'OpenSearch is not reachable at http://localhost:9200'
    }
    Write-Host "PASS: Services are reachable" -ForegroundColor Green

    Write-Step "4) Seeding resource + ACL on host-mounted storage"
    $storageRoot = Join-Path $PSScriptRoot 'resource_server\app\storage'
    $resourcePath = Join-Path $storageRoot 'r\docs\report.txt'
    $aclPath = Join-Path $storageRoot 'acl\docs\report.txt.ttl'

    New-Item -ItemType Directory -Path (Split-Path $resourcePath -Parent) -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path $aclPath -Parent) -Force | Out-Null

    Write-Utf8NoBom -Path $resourcePath -Content "Quarterly report`n"

    $ttl = @'
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#read-public>
  a acl:Authorization ;
  acl:accessTo <http://resource:8001/r/docs/report.txt> ;
  acl:mode acl:Read ;
  acl:agentClass foaf:Agent .

<#write-alice>
  a acl:Authorization ;
  acl:accessTo <http://resource:8001/r/docs/report.txt> ;
  acl:mode acl:Write ;
  acl:agent <https://alice.example/profile#me> .
'@
    Write-Utf8NoBom -Path $aclPath -Content $ttl
    Write-Host "PASS: Demo data seeded" -ForegroundColor Green

    Write-Step "5) Authorization demo"
    $getPublic = Invoke-DemoRequest -Method GET -Uri 'http://localhost:8000/r/docs/report.txt'
    Assert-Equal -actual $getPublic.StatusCode -expected 200 -label 'Public GET through guard'

    $denyWrite = Invoke-DemoRequest -Method PUT -Uri 'http://localhost:8000/r/docs/report.txt' -Body 'Anonymous edit'
    Assert-Equal -actual $denyWrite.StatusCode -expected 403 -label 'Anonymous PUT denied'

    # Additional denied attempts to trigger brute-force threshold (default 5 in 60s)
    for ($i = 1; $i -le 4; $i++) {
        $extraDeny = Invoke-DemoRequest -Method PUT -Uri 'http://localhost:8000/r/docs/report.txt' -Body "Anonymous edit $i"
        Assert-Equal -actual $extraDeny.StatusCode -expected 403 -label "Anonymous PUT denied #$($i + 1)"
    }

    $aliceHeaders = @{ 'X-WebID' = 'https://alice.example/profile#me' }
    $allowWrite = Invoke-DemoRequest -Method PUT -Uri 'http://localhost:8000/r/docs/report.txt' -Headers $aliceHeaders -Body 'Alice update'
    Assert-Equal -actual $allowWrite.StatusCode -expected 204 -label 'Alice PUT allowed'

    $getAfter = Invoke-DemoRequest -Method GET -Uri 'http://localhost:8000/r/docs/report.txt'
    Assert-Equal -actual $getAfter.StatusCode -expected 200 -label 'GET after Alice PUT'
    if ($getAfter.Content -notmatch 'Alice update') {
        throw 'Expected updated resource content to contain: Alice update'
    }
    Write-Host "PASS: Updated content observed" -ForegroundColor Green

        Write-Step "6) Querying OpenSearch for security telemetry"
    $queryBody = @'
{
    "size": 20,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {"match_all": {}}
}
'@
    $search = Invoke-RestMethod -Method POST -Uri 'http://localhost:9200/webauthguard-events-*/_search' -ContentType 'application/json' -Body $queryBody

    $hits = $search.hits.hits
    if (-not $hits -or $hits.Count -lt 1) {
        throw 'No events found in OpenSearch index pattern webauthguard-events-*'
    }

    Write-Host "PASS: Found $($hits.Count) recent OpenSearch event(s)" -ForegroundColor Green

    $hasFailedIp = $false
    $hasSuccessIp = $false
    $hasThreat = $false

    foreach ($hit in $hits) {
        $security = $hit._source.security
        if ($null -ne $security) {
            if ($security.failed_ip) { $hasFailedIp = $true }
            if ($security.success_ip) { $hasSuccessIp = $true }
            if ($security.possible_threat -eq $true) { $hasThreat = $true }
        }
    }

    if (-not $hasFailedIp) {
        throw 'No security.failed_ip found in recent events'
    }
    if (-not $hasSuccessIp) {
        throw 'No security.success_ip found in recent events'
    }
    if (-not $hasThreat) {
        throw 'No security.possible_threat=true found in recent events'
    }

    Write-Host "PASS: security.failed_ip present" -ForegroundColor Green
    Write-Host "PASS: security.success_ip present" -ForegroundColor Green
    Write-Host "PASS: security.possible_threat=true present" -ForegroundColor Green

    Write-Step "Demo complete"
    Write-Host "All checks passed." -ForegroundColor Green
    Write-Host "Guard docs:     http://localhost:8000/docs"
    Write-Host "Resource docs:  http://localhost:8001/docs"
    Write-Host "OpenSearch:     http://localhost:9200"
    Write-Host "Dashboards:     http://localhost:5601"

    exit 0
}
catch {
    Write-Host "`nDEMO FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Try: docker compose logs -f guard resource opensearch dashboards"
    exit 1
}
