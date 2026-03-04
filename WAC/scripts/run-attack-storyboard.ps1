param(
    [string]$BaseUrl = "http://localhost:8000",
    [string]$RunId = ("run-" + (Get-Date -Format "yyyyMMdd-HHmmss")),
    [string]$TargetUser = "admin",
    [string]$WrongPassword = "Wrong123!",
    [ValidateSet("all", "baseline_success", "account_bruteforce", "credential_stuffing", "distributed_account_attack", "parallel_session_violation", "vpn_geo_anomaly")]
    [string]$Scenario = "all"
)

$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Invoke-FormPost {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][hashtable]$Body,
        [hashtable]$Headers
    )

    try {
        $params = @{
            Method = 'POST'
            Uri = $Uri
            Body = $Body
            ContentType = 'application/x-www-form-urlencoded'
            TimeoutSec = 20
            MaximumRedirection = 0
            UseBasicParsing = $true
        }
        if ($Headers) { $params.Headers = $Headers }
        $resp = Invoke-WebRequest @params
        return [pscustomobject]@{
            StatusCode = [int]$resp.StatusCode
            Content = $resp.Content
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
                Content = $content
            }
        }
        throw
    }
}

function Invoke-Login {
    param(
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$SessionId,
        [Parameter(Mandatory = $true)][string]$Scenario,
        [string]$ClientLabel = "attacker",
        [string]$CountryCode,
        [bool]$VpnSuspected = $false
    )

    $headers = @{
        'X-Demo-Run-ID' = $RunId
        'X-Demo-Scenario' = $Scenario
        'X-Client-Label' = $ClientLabel
        'X-Session-ID' = $SessionId
    }
    if ($CountryCode) { $headers['X-Country'] = $CountryCode }
    if ($VpnSuspected) { $headers['X-VPN-Suspected'] = 'true' }

    $body = @{
        username = $Username
        password = $Password
        session_id = $SessionId
    }
    if ($CountryCode) { $body['country_code_form'] = $CountryCode }
    if ($VpnSuspected) { $body['vpn_suspected_form'] = 'true' }

    return Invoke-FormPost -Uri "$BaseUrl/login" -Body $body -Headers $headers
}

function Invoke-Signup {
    param(
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][string]$Email,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$SessionId
    )

    $headers = @{
        'X-Demo-Run-ID' = $RunId
        'X-Demo-Scenario' = 'bootstrap_account'
        'X-Client-Label' = 'setup'
        'X-Session-ID' = $SessionId
    }

    $body = @{
        username = $Username
        email = $Email
        password = $Password
        confirm_password = $Password
        session_id = $SessionId
    }

    return Invoke-FormPost -Uri "$BaseUrl/signup" -Body $body -Headers $headers
}

function Write-ScenarioResult {
    param(
        [string]$Scenario,
        [string]$ExpectedThreats,
        [int[]]$StatusCodes
    )

    $joinedCodes = ($StatusCodes | ForEach-Object { "$_" }) -join ","
    Write-Host "scenario=$Scenario"
    Write-Host "http_statuses=$joinedCodes"
    Write-Host "expected_threat_types=$ExpectedThreats"
    Write-Host "run_id=$RunId"
}

$targetPassword = $env:WAC_TARGET_PASSWORD
if (-not $targetPassword) {
    $targetPassword = "Admin123!"
}

$activeUser = $TargetUser
$activePassword = $targetPassword

Write-Step "Pre-check: Ensure target account can login"
$baselineTry = Invoke-Login -Username $activeUser -Password $activePassword -SessionId "baseline-setup" -Scenario "baseline_precheck" -ClientLabel "normal-user"
if ($baselineTry.StatusCode -ne 303 -and $baselineTry.StatusCode -ne 302 -and $baselineTry.StatusCode -ne 200) {
    Write-Host "Initial login failed for '$activeUser' (status=$($baselineTry.StatusCode)). Attempting signup with this username..."
    $signupTry = Invoke-Signup -Username $activeUser -Email "$($activeUser)+demo@example.local" -Password $activePassword -SessionId "signup-$RunId"
    if ($signupTry.StatusCode -eq 400) {
        $activeUser = "socdemo_$($RunId.Replace('-', '').ToLower())"
        $activePassword = "Demo!12345"
        Write-Host "Username already exists. Switching to fallback user '$activeUser'."
        $signupTry = Invoke-Signup -Username $activeUser -Email "$($activeUser)@example.local" -Password $activePassword -SessionId "signup-fallback-$RunId"
    }
    $baselineTry = Invoke-Login -Username $activeUser -Password $activePassword -SessionId "baseline-setup-2" -Scenario "baseline_precheck" -ClientLabel "normal-user"
}

if ($baselineTry.StatusCode -ne 303 -and $baselineTry.StatusCode -ne 302 -and $baselineTry.StatusCode -ne 200) {
    throw "Unable to establish a baseline valid account. Last status=$($baselineTry.StatusCode)"
}

Write-Host "Using target account: $activeUser"
Write-Host "Run ID: $RunId"

function Invoke-BaselineSuccess {
    Write-Step "1) Baseline success login"
    $codes = @()
    $resp = Invoke-Login -Username $activeUser -Password $activePassword -SessionId "baseline-1" -Scenario "baseline_success" -ClientLabel "normal-user"
    $codes += $resp.StatusCode
    Write-ScenarioResult -Scenario "baseline_success" -ExpectedThreats "none" -StatusCodes $codes
}

function Invoke-AccountBruteforce {
    Write-Step "2) Account brute force (same account, repeated failures)"
    $codes = @()
    1..6 | ForEach-Object {
        $resp = Invoke-Login -Username $activeUser -Password $WrongPassword -SessionId "bf-1" -Scenario "account_bruteforce" -ClientLabel "attacker"
        $codes += $resp.StatusCode
    }
    Write-ScenarioResult -Scenario "account_bruteforce" -ExpectedThreats "brute_force,account_brute_force" -StatusCodes $codes
}

function Invoke-CredentialStuffing {
    Write-Step "3) Credential stuffing (many usernames, same source)"
    $codes = @()
    "alice", "bob", "carol", "dave", "erin", "frank" | ForEach-Object {
        $resp = Invoke-Login -Username $_ -Password $WrongPassword -SessionId "stuff-1" -Scenario "credential_stuffing" -ClientLabel "attacker"
        $codes += $resp.StatusCode
    }
    Write-ScenarioResult -Scenario "credential_stuffing" -ExpectedThreats "credential_stuffing" -StatusCodes $codes
}

function Invoke-DistributedAccountAttack {
    Write-Step "4) Distributed account attack (same account, multiple sessions)"
    $codes = @()
    1..4 | ForEach-Object {
        $session = "dist-$($_)"
        $resp = Invoke-Login -Username $activeUser -Password $WrongPassword -SessionId $session -Scenario "distributed_account_attack" -ClientLabel "attacker"
        $codes += $resp.StatusCode
    }
    Write-ScenarioResult -Scenario "distributed_account_attack" -ExpectedThreats "distributed_account_attack" -StatusCodes $codes
}

function Invoke-ParallelSessionViolation {
    Write-Step "5) Parallel session policy violation (>4 active sessions)"
    $codes = @()
    1..5 | ForEach-Object {
        $session = "parallel-$($_)"
        $resp = Invoke-Login -Username $activeUser -Password $activePassword -SessionId $session -Scenario "parallel_session_violation" -ClientLabel "normal-user"
        $codes += $resp.StatusCode
    }
    Write-ScenarioResult -Scenario "parallel_session_violation" -ExpectedThreats "parallel_session_policy_violation" -StatusCodes $codes
}

function Invoke-VpnGeoAnomaly {
    Write-Step "6) VPN/Geo anomaly deterministic trigger"
    $codes = @()
    $respUs = Invoke-Login -Username $activeUser -Password $activePassword -SessionId "geo-us" -Scenario "vpn_geo_anomaly" -ClientLabel "vpn-client" -CountryCode "US" -VpnSuspected $true
    $respDe = Invoke-Login -Username $activeUser -Password $activePassword -SessionId "geo-de" -Scenario "vpn_geo_anomaly" -ClientLabel "vpn-client" -CountryCode "DE" -VpnSuspected $true
    $codes += $respUs.StatusCode
    $codes += $respDe.StatusCode
    Write-ScenarioResult -Scenario "vpn_geo_anomaly" -ExpectedThreats "vpn_geography_anomaly,vpn_proxy_network" -StatusCodes $codes
}

switch ($Scenario) {
    "all" {
        Invoke-BaselineSuccess
        Invoke-AccountBruteforce
        Invoke-CredentialStuffing
        Invoke-DistributedAccountAttack
        Invoke-ParallelSessionViolation
        Invoke-VpnGeoAnomaly
    }
    "baseline_success" { Invoke-BaselineSuccess }
    "account_bruteforce" { Invoke-AccountBruteforce }
    "credential_stuffing" { Invoke-CredentialStuffing }
    "distributed_account_attack" { Invoke-DistributedAccountAttack }
    "parallel_session_violation" { Invoke-ParallelSessionViolation }
    "vpn_geo_anomaly" { Invoke-VpnGeoAnomaly }
}

Write-Step "Storyboard complete"
Write-Host "Executed scenario=$Scenario"
Write-Host "Filter dashboard with demo.run_id = $RunId"
Write-Host "Open: http://localhost/dashboards/"
