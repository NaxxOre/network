$ErrorActionPreference = 'Stop'

$headers = @{ 'osd-xsrf' = 'true'; 'Content-Type' = 'application/json' }
$indexId = 'f1a7cd82-c853-49cd-8323-728e26b33bc0'
$dashboardId = '81a7fc9b-0839-4a7d-b5ca-df7bc3f9292b'
$dashboardTitle = 'WebAuthGuard Security Overview'
$dashboardsApiBase = 'http://localhost:5601/dashboards'

function Invoke-Osd {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [string]$Body
    )

    if ($Body) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $Body -UseBasicParsing
    }
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers @{ 'osd-xsrf' = 'true' } -UseBasicParsing
}

function Build-SearchSourceJson {
    param(
        [Parameter(Mandatory = $true)][string]$Query
    )
    $searchSourceObj = @{
        query = @{ language = 'kuery'; query = $Query }
        filter = @()
        indexRefName = 'kibanaSavedObjectMeta.searchSourceJSON.index'
    }
    return ($searchSourceObj | ConvertTo-Json -Compress -Depth 25)
}

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

    $payloadObj = @{
        attributes = @{
            title = $Title
            visState = ($visStateObj | ConvertTo-Json -Compress -Depth 25)
            uiStateJSON = '{}'
            description = $Title
            version = 1
            kibanaSavedObjectMeta = @{ searchSourceJSON = (Build-SearchSourceJson -Query $Query) }
        }
        references = @(
            @{ name = 'kibanaSavedObjectMeta.searchSourceJSON.index'; type = 'index-pattern'; id = $indexId }
        )
    }

    $payload = $payloadObj | ConvertTo-Json -Compress -Depth 40
    Invoke-Osd -Method POST -Uri "$dashboardsApiBase/api/saved_objects/visualization/${Id}?overwrite=true" -Body $payload | Out-Null
}

function Upsert-MetricVisualization {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Query
    )

    $visStateObj = @{
        title = $Title
        type = 'metric'
        params = @{ addTooltip = $true; addLegend = $false }
        aggs = @(
            @{ id = '1'; enabled = $true; type = 'count'; schema = 'metric'; params = @{} }
        )
    }

    $payloadObj = @{
        attributes = @{
            title = $Title
            visState = ($visStateObj | ConvertTo-Json -Compress -Depth 25)
            uiStateJSON = '{}'
            description = $Title
            version = 1
            kibanaSavedObjectMeta = @{ searchSourceJSON = (Build-SearchSourceJson -Query $Query) }
        }
        references = @(
            @{ name = 'kibanaSavedObjectMeta.searchSourceJSON.index'; type = 'index-pattern'; id = $indexId }
        )
    }

    $payload = $payloadObj | ConvertTo-Json -Compress -Depth 40
    Invoke-Osd -Method POST -Uri "$dashboardsApiBase/api/saved_objects/visualization/${Id}?overwrite=true" -Body $payload | Out-Null
}

function Upsert-PieVisualization {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Query,
        [Parameter(Mandatory = $true)][string]$Field
    )

    $visStateObj = @{
        title = $Title
        type = 'pie'
        params = @{
            addTooltip = $true
            addLegend = $true
            legendPosition = 'right'
            isDonut = $true
            labels = @{
                show = $true
                values = $true
                last_level = $true
                truncate = 100
            }
        }
        aggs = @(
            @{ id = '1'; enabled = $true; type = 'count'; schema = 'metric'; params = @{} },
            @{ id = '2'; enabled = $true; type = 'terms'; schema = 'segment'; params = @{ field = $Field; size = 8; order = 'desc'; orderBy = '1' } }
        )
    }

    $payloadObj = @{
        attributes = @{
            title = $Title
            visState = ($visStateObj | ConvertTo-Json -Compress -Depth 25)
            uiStateJSON = '{}'
            description = $Title
            version = 1
            kibanaSavedObjectMeta = @{ searchSourceJSON = (Build-SearchSourceJson -Query $Query) }
        }
        references = @(
            @{ name = 'kibanaSavedObjectMeta.searchSourceJSON.index'; type = 'index-pattern'; id = $indexId }
        )
    }

    $payload = $payloadObj | ConvertTo-Json -Compress -Depth 40
    Invoke-Osd -Method POST -Uri "$dashboardsApiBase/api/saved_objects/visualization/${Id}?overwrite=true" -Body $payload | Out-Null
}

function Upsert-SavedSearch {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Title
    )

    $searchSourceObj = @{
        query = @{ language = 'kuery'; query = 'security.event_type : "auth_login"' }
        filter = @()
        indexRefName = 'kibanaSavedObjectMeta.searchSourceJSON.index'
    }

    $payloadObj = @{
        attributes = @{
            title = $Title
            description = 'Raw auth log monitor'
            columns = @(
                '@timestamp',
                'src_ip',
                'agent.username',
                'security.threat_types',
                'security.threat_level',
                'security.country_code',
                'security.vpn_suspected',
                'security.session_id',
                'demo.scenario',
                'demo.run_id'
            )
            sort = @(
                @('@timestamp', 'desc')
            )
            kibanaSavedObjectMeta = @{
                searchSourceJSON = ($searchSourceObj | ConvertTo-Json -Compress -Depth 25)
            }
        }
        references = @(
            @{ name = 'kibanaSavedObjectMeta.searchSourceJSON.index'; type = 'index-pattern'; id = $indexId }
        )
    }

    $payload = $payloadObj | ConvertTo-Json -Compress -Depth 40
    Invoke-Osd -Method POST -Uri "$dashboardsApiBase/api/saved_objects/search/${Id}?overwrite=true" -Body $payload | Out-Null
}

function Add-Or-Update-Panel {
    param(
        [Parameter(Mandatory = $true)][array]$Panels,
        [Parameter(Mandatory = $true)][string]$PanelRefName,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$PanelIndex,
        [Parameter(Mandatory = $true)][hashtable]$GridData
    )

    $existing = $Panels | Where-Object { $_.panelRefName -eq $PanelRefName }
    if ($existing) {
        $existing.type = $Type
        $existing.panelIndex = $PanelIndex
        $existing.gridData = $GridData
        $existing.version = '8.0.0'
        if (-not $existing.embeddableConfig) { $existing | Add-Member -NotePropertyName embeddableConfig -NotePropertyValue @{} -Force }
        return $Panels
    }

    $newPanel = @{
        version = '8.0.0'
        type = $Type
        panelIndex = $PanelIndex
        gridData = $GridData
        embeddableConfig = @{}
        panelRefName = $PanelRefName
    }
    return @($Panels + $newPanel)
}

function Ensure-Reference {
    param(
        [Parameter(Mandatory = $true)][array]$References,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Id
    )

    $existing = $References | Where-Object { $_.name -eq $Name }
    if ($existing) {
        $existing.type = $Type
        $existing.id = $Id
        return $References
    }

    return @($References + @{ name = $Name; type = $Type; id = $Id })
}

Write-Host "Upserting showcase visualizations..."
Upsert-TableVisualization -Id 'wac-vis-top-targeted-accounts' -Title 'Top Targeted Accounts' -Query 'security.event_type : "auth_login" and security.login_result : "failed"' -Field 'agent.username.keyword'
Upsert-PieVisualization -Id 'wac-vis-threat-type-distribution' -Title 'Threat Type Distribution' -Query 'security.possible_threat : true and security.event_type : "auth_login"' -Field 'security.threat_types.keyword'
Upsert-MetricVisualization -Id 'wac-vis-credential-stuffing-count' -Title 'Credential Stuffing Events' -Query 'security.credential_stuffing : true'
Upsert-MetricVisualization -Id 'wac-vis-distributed-attack-count' -Title 'Distributed Account Attack Events' -Query 'security.distributed_account_attack : true'
Upsert-SavedSearch -Id 'wac-search-auth-log-monitor' -Title 'WAC Auth Log Monitor'

Write-Host "Updating dashboard layout..."
$dash = $null
$resolvedDashboardId = $dashboardId
try {
    $dash = Invoke-Osd -Method GET -Uri "$dashboardsApiBase/api/saved_objects/dashboard/$resolvedDashboardId"
}
catch {
    $find = Invoke-Osd -Method GET -Uri "$dashboardsApiBase/api/saved_objects/_find?type=dashboard&search_fields=title&search=WebAuthGuard*"
    $candidate = $find.saved_objects | Where-Object { $_.attributes.title -eq $dashboardTitle } | Select-Object -First 1
    if (-not $candidate) {
        throw "Dashboard '$dashboardTitle' not found in current Dashboards instance. Import .\opensearch\webauthguard-security-dashboard.ndjson first."
    }
    $resolvedDashboardId = $candidate.id
    $dash = Invoke-Osd -Method GET -Uri "$dashboardsApiBase/api/saved_objects/dashboard/$resolvedDashboardId"
}
$panels = @($dash.attributes.panelsJSON | ConvertFrom-Json)
$references = @($dash.references)

$references = Ensure-Reference -References $references -Name 'panel_13' -Type 'visualization' -Id 'wac-vis-top-targeted-accounts'
$references = Ensure-Reference -References $references -Name 'panel_14' -Type 'visualization' -Id 'wac-vis-threat-type-distribution'
$references = Ensure-Reference -References $references -Name 'panel_15' -Type 'visualization' -Id 'wac-vis-credential-stuffing-count'
$references = Ensure-Reference -References $references -Name 'panel_16' -Type 'visualization' -Id 'wac-vis-distributed-attack-count'
$references = Ensure-Reference -References $references -Name 'panel_17' -Type 'search' -Id 'wac-search-auth-log-monitor'

$panels = Add-Or-Update-Panel -Panels $panels -PanelRefName 'panel_13' -Type 'visualization' -PanelIndex '13' -GridData @{ x = 0; y = 62; w = 16; h = 10; i = '13' }
$panels = Add-Or-Update-Panel -Panels $panels -PanelRefName 'panel_14' -Type 'visualization' -PanelIndex '14' -GridData @{ x = 16; y = 62; w = 16; h = 10; i = '14' }
$panels = Add-Or-Update-Panel -Panels $panels -PanelRefName 'panel_15' -Type 'visualization' -PanelIndex '15' -GridData @{ x = 32; y = 62; w = 16; h = 10; i = '15' }
$panels = Add-Or-Update-Panel -Panels $panels -PanelRefName 'panel_16' -Type 'visualization' -PanelIndex '16' -GridData @{ x = 0; y = 72; w = 16; h = 10; i = '16' }
$panels = Add-Or-Update-Panel -Panels $panels -PanelRefName 'panel_17' -Type 'search' -PanelIndex '17' -GridData @{ x = 16; y = 72; w = 32; h = 16; i = '17' }

$dash.attributes.title = 'WebAuthGuard Security Overview'
$dash.attributes.panelsJSON = ($panels | ConvertTo-Json -Compress -Depth 25)
$dashPayload = @{ attributes = $dash.attributes; references = $references } | ConvertTo-Json -Compress -Depth 50
Invoke-Osd -Method PUT -Uri "$dashboardsApiBase/api/saved_objects/dashboard/$resolvedDashboardId" -Body $dashPayload | Out-Null

Write-Host "Exporting updated dashboard NDJSON..."
$exportReq = (@{ objects = @(@{ type = 'dashboard'; id = $resolvedDashboardId }); includeReferencesDeep = $true } | ConvertTo-Json -Compress)
$export = Invoke-Osd -Method POST -Uri "$dashboardsApiBase/api/saved_objects/_export" -Body $exportReq
$targetPath = Resolve-Path (Join-Path $PSScriptRoot '..\opensearch\webauthguard-security-dashboard.ndjson')
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($targetPath, $export, $utf8NoBom)

Write-Host "Showcase dashboard update complete."
