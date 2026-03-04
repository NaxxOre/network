$ErrorActionPreference = 'Stop'

$headers = @{ 'osd-xsrf' = 'true'; 'Content-Type' = 'application/json' }
$indexId = 'f1a7cd82-c853-49cd-8323-728e26b33bc0'
$dashboardId = '81a7fc9b-0839-4a7d-b5ca-df7bc3f9292b'

function Upsert-TableVisualization {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Query,
        [Parameter(Mandatory = $true)][string]$Field
    )

    $visStateObj = @{
        title = $Title
        type = 'table'
        params = @{
            perPage = 10
            showPartialRows = $false
            showMetricsAtAllLevels = $false
            sort = @{ columnIndex = $null; direction = $null }
        }
        aggs = @(
            @{ id = '1'; enabled = $true; type = 'count'; schema = 'metric'; params = @{} },
            @{ id = '2'; enabled = $true; type = 'terms'; schema = 'bucket'; params = @{ field = $Field; size = 10; order = 'desc'; orderBy = '1' } }
        )
    }

    $searchSourceObj = @{
        query = @{ language = 'kuery'; query = $Query }
        filter = @()
        indexRefName = 'kibanaSavedObjectMeta.searchSourceJSON.index'
    }

    $payloadObj = @{
        attributes = @{
            title = $Title
            visState = ($visStateObj | ConvertTo-Json -Compress -Depth 20)
            uiStateJSON = '{}'
            description = $Title
            version = 1
            kibanaSavedObjectMeta = @{ searchSourceJSON = ($searchSourceObj | ConvertTo-Json -Compress -Depth 20) }
        }
        references = @(
            @{ name = 'kibanaSavedObjectMeta.searchSourceJSON.index'; type = 'index-pattern'; id = $indexId }
        )
    }

    $payload = $payloadObj | ConvertTo-Json -Compress -Depth 30
    Invoke-RestMethod -Method POST -Uri "http://localhost:5601/api/saved_objects/visualization/${Id}?overwrite=true" -Headers $headers -Body $payload -UseBasicParsing | Out-Null
}

Upsert-TableVisualization -Id 'wac-vis-auth-ip-account-failed' -Title 'Auth Failed Attempts by IP and Account' -Query 'security.event_type : "auth_login" and security.login_result : "failed"' -Field 'security.ip_account_key.keyword'
Upsert-TableVisualization -Id 'wac-vis-auth-ip-account-success' -Title 'Auth Success Attempts by IP and Account' -Query 'security.event_type : "auth_login" and security.login_result : "success"' -Field 'security.ip_account_key.keyword'

$dash = Invoke-RestMethod -Method GET -Uri "http://localhost:5601/api/saved_objects/dashboard/$dashboardId" -Headers @{ 'osd-xsrf' = 'true' } -UseBasicParsing
$panels = $dash.attributes.panelsJSON | ConvertFrom-Json

if (-not ($dash.references | Where-Object { $_.name -eq 'panel_11' })) {
    $dash.references += @{ name = 'panel_11'; type = 'visualization'; id = 'wac-vis-auth-ip-account-failed' }
    $panels += @{ version = '8.0.0'; type = 'visualization'; panelIndex = '11'; gridData = @{ x = 0; y = 50; w = 24; h = 12; i = '11' }; embeddableConfig = @{}; panelRefName = 'panel_11' }
}
if (-not ($dash.references | Where-Object { $_.name -eq 'panel_12' })) {
    $dash.references += @{ name = 'panel_12'; type = 'visualization'; id = 'wac-vis-auth-ip-account-success' }
    $panels += @{ version = '8.0.0'; type = 'visualization'; panelIndex = '12'; gridData = @{ x = 24; y = 50; w = 24; h = 12; i = '12' }; embeddableConfig = @{}; panelRefName = 'panel_12' }
}

$dash.attributes.panelsJSON = ($panels | ConvertTo-Json -Compress -Depth 25)
$dashPayload = @{ attributes = $dash.attributes; references = $dash.references } | ConvertTo-Json -Compress -Depth 50
Invoke-RestMethod -Method PUT -Uri "http://localhost:5601/api/saved_objects/dashboard/$dashboardId" -Headers $headers -Body $dashPayload -UseBasicParsing | Out-Null

$exportReq = '{"objects":[{"type":"dashboard","id":"81a7fc9b-0839-4a7d-b5ca-df7bc3f9292b"}],"includeReferencesDeep":true}'
$export = Invoke-RestMethod -Method POST -Uri 'http://localhost:5601/api/saved_objects/_export' -Headers $headers -Body $exportReq -UseBasicParsing

$targetPath = Resolve-Path '.\opensearch\webauthguard-security-dashboard.ndjson'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($targetPath, $export, $utf8NoBom)

Write-Host 'Dashboard updated with IP-account auth attempt tables and exported without BOM.'
