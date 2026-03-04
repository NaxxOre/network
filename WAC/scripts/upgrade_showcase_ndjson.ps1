$ErrorActionPreference = 'Stop'

$ndjsonPath = Join-Path $PSScriptRoot '..\opensearch\webauthguard-security-dashboard.ndjson'
$indexId = 'f1a7cd82-c853-49cd-8323-728e26b33bc0'
$dashboardId = '81a7fc9b-0839-4a7d-b5ca-df7bc3f9292b'

function To-CompactJson([object]$Value, [int]$Depth = 80) {
    $safeDepth = [Math]::Min([Math]::Max($Depth, 2), 100)
    return ($Value | ConvertTo-Json -Compress -Depth $safeDepth)
}

function New-VisualizationObject {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Query,
        [Parameter(Mandatory = $true)][array]$Aggs,
        [hashtable]$Params = @{}
    )

    $visState = @{
        title = $Title
        type = $Type
        params = $Params
        aggs = $Aggs
    }
    $searchSource = @{
        query = @{ language = 'kuery'; query = $Query }
        filter = @()
        indexRefName = 'kibanaSavedObjectMeta.searchSourceJSON.index'
    }
    return [ordered]@{
        type = 'visualization'
        id = $Id
        attributes = @{
            title = $Title
            description = $Title
            uiStateJSON = '{}'
            version = 1
            visState = (To-CompactJson $visState 40)
            kibanaSavedObjectMeta = @{
                searchSourceJSON = (To-CompactJson $searchSource 30)
            }
        }
        references = @(
            @{ name = 'kibanaSavedObjectMeta.searchSourceJSON.index'; type = 'index-pattern'; id = $indexId }
        )
    }
}

function New-SearchObject {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Title
    )

    $searchSource = @{
        query = @{ language = 'kuery'; query = 'security.event_type : "auth_login"' }
        filter = @()
        indexRefName = 'kibanaSavedObjectMeta.searchSourceJSON.index'
    }

    return [ordered]@{
        type = 'search'
        id = $Id
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
                searchSourceJSON = (To-CompactJson $searchSource 30)
            }
        }
        references = @(
            @{ name = 'kibanaSavedObjectMeta.searchSourceJSON.index'; type = 'index-pattern'; id = $indexId }
        )
    }
}

function Upsert-Object {
    param(
        [Parameter(Mandatory = $true)][System.Collections.ArrayList]$Objects,
        [Parameter(Mandatory = $true)][hashtable]$Object
    )

    for ($i = 0; $i -lt $Objects.Count; $i++) {
        if ($Objects[$i].type -eq $Object.type -and $Objects[$i].id -eq $Object.id) {
            $Objects[$i] = [pscustomobject]$Object
            return
        }
    }
    [void]$Objects.Add([pscustomobject]$Object)
}

function Ensure-IndexField {
    param(
        [Parameter(Mandatory = $true)][System.Collections.ArrayList]$Fields,
        [Parameter(Mandatory = $true)][hashtable]$FieldDef
    )

    for ($i = 0; $i -lt $Fields.Count; $i++) {
        if ($Fields[$i].name -eq $FieldDef.name) {
            $Fields[$i] = [pscustomobject]$FieldDef
            return
        }
    }
    [void]$Fields.Add([pscustomobject]$FieldDef)
}

function Ensure-Reference {
    param(
        [Parameter(Mandatory = $true)][System.Collections.ArrayList]$References,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Id
    )

    for ($i = 0; $i -lt $References.Count; $i++) {
        if ($References[$i].name -eq $Name) {
            $References[$i].type = $Type
            $References[$i].id = $Id
            return
        }
    }
    [void]$References.Add([pscustomobject]@{ name = $Name; type = $Type; id = $Id })
}

function Ensure-Panel {
    param(
        [Parameter(Mandatory = $true)][System.Collections.ArrayList]$Panels,
        [Parameter(Mandatory = $true)][string]$PanelRefName,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$PanelIndex,
        [Parameter(Mandatory = $true)][hashtable]$Grid
    )

    for ($i = 0; $i -lt $Panels.Count; $i++) {
        if ($Panels[$i].panelRefName -eq $PanelRefName) {
            $Panels[$i].type = $Type
            $Panels[$i].panelIndex = $PanelIndex
            $Panels[$i].gridData = [pscustomobject]$Grid
            $Panels[$i].version = '8.0.0'
            if (-not $Panels[$i].embeddableConfig) {
                $Panels[$i] | Add-Member -NotePropertyName embeddableConfig -NotePropertyValue @{} -Force
            }
            return
        }
    }

    [void]$Panels.Add([pscustomobject]@{
        version = '8.0.0'
        type = $Type
        panelIndex = $PanelIndex
        gridData = [pscustomobject]$Grid
        embeddableConfig = @{}
        panelRefName = $PanelRefName
    })
}

if (-not (Test-Path $ndjsonPath)) {
    throw "NDJSON not found: $ndjsonPath"
}

$objects = New-Object System.Collections.ArrayList
Get-Content $ndjsonPath | Where-Object { $_.Trim() } | ForEach-Object {
    $parsed = $_ | ConvertFrom-Json
    if ($parsed.type -and $parsed.id) {
        [void]$objects.Add($parsed)
    }
}

$topAccountsVis = New-VisualizationObject -Id 'wac-vis-top-targeted-accounts' -Title 'Top Targeted Accounts' -Type 'table' -Query 'security.event_type : "auth_login" and security.login_result : "failed"' -Aggs @(
    @{ id = '1'; enabled = $true; type = 'count'; schema = 'metric'; params = @{} },
    @{ id = '2'; enabled = $true; type = 'terms'; schema = 'bucket'; params = @{ field = 'agent.username.keyword'; size = 10; order = 'desc'; orderBy = '1' } }
) -Params @{
    perPage = 10
    showPartialRows = $false
    showMetricsAtAllLevels = $false
    sort = @{ columnIndex = $null; direction = $null }
}

$threatDistVis = New-VisualizationObject -Id 'wac-vis-threat-type-distribution' -Title 'Threat Type Distribution' -Type 'pie' -Query 'security.possible_threat : true and security.event_type : "auth_login"' -Aggs @(
    @{ id = '1'; enabled = $true; type = 'count'; schema = 'metric'; params = @{} },
    @{ id = '2'; enabled = $true; type = 'terms'; schema = 'segment'; params = @{ field = 'security.threat_types.keyword'; size = 8; order = 'desc'; orderBy = '1' } }
) -Params @{
    addTooltip = $true
    addLegend = $true
    legendPosition = 'right'
    isDonut = $true
    labels = @{ show = $true; values = $true; last_level = $true; truncate = 100 }
}

$credentialStuffingVis = New-VisualizationObject -Id 'wac-vis-credential-stuffing-count' -Title 'Credential Stuffing Events' -Type 'metric' -Query 'security.credential_stuffing : true' -Aggs @(
    @{ id = '1'; enabled = $true; type = 'count'; schema = 'metric'; params = @{} }
) -Params @{
    addTooltip = $true
    addLegend = $false
}

$distributedAttackVis = New-VisualizationObject -Id 'wac-vis-distributed-attack-count' -Title 'Distributed Account Attack Events' -Type 'metric' -Query 'security.distributed_account_attack : true' -Aggs @(
    @{ id = '1'; enabled = $true; type = 'count'; schema = 'metric'; params = @{} }
) -Params @{
    addTooltip = $true
    addLegend = $false
}

$authLogSearch = New-SearchObject -Id 'wac-search-auth-log-monitor' -Title 'WAC Auth Log Monitor'

Upsert-Object -Objects $objects -Object $topAccountsVis
Upsert-Object -Objects $objects -Object $threatDistVis
Upsert-Object -Objects $objects -Object $credentialStuffingVis
Upsert-Object -Objects $objects -Object $distributedAttackVis
Upsert-Object -Objects $objects -Object $authLogSearch

$indexPattern = $objects | Where-Object { $_.type -eq 'index-pattern' -and $_.id -eq $indexId } | Select-Object -First 1
if ($indexPattern -and $indexPattern.attributes.fields) {
    $fields = New-Object System.Collections.ArrayList
    ($indexPattern.attributes.fields | ConvertFrom-Json) | ForEach-Object { [void]$fields.Add($_) }

    Ensure-IndexField -Fields $fields -FieldDef @{
        count = 0; name = 'demo.run_id'; type = 'string'; esTypes = @('text'); scripted = $false; searchable = $true; aggregatable = $false; readFromDocValues = $false
    }
    Ensure-IndexField -Fields $fields -FieldDef @{
        count = 0; name = 'demo.run_id.keyword'; type = 'string'; esTypes = @('keyword'); scripted = $false; searchable = $true; aggregatable = $true; readFromDocValues = $true; subType = @{ multi = @{ parent = 'demo.run_id' } }
    }
    Ensure-IndexField -Fields $fields -FieldDef @{
        count = 0; name = 'demo.scenario'; type = 'string'; esTypes = @('text'); scripted = $false; searchable = $true; aggregatable = $false; readFromDocValues = $false
    }
    Ensure-IndexField -Fields $fields -FieldDef @{
        count = 0; name = 'demo.scenario.keyword'; type = 'string'; esTypes = @('keyword'); scripted = $false; searchable = $true; aggregatable = $true; readFromDocValues = $true; subType = @{ multi = @{ parent = 'demo.scenario' } }
    }
    Ensure-IndexField -Fields $fields -FieldDef @{
        count = 0; name = 'demo.client_label'; type = 'string'; esTypes = @('text'); scripted = $false; searchable = $true; aggregatable = $false; readFromDocValues = $false
    }
    Ensure-IndexField -Fields $fields -FieldDef @{
        count = 0; name = 'demo.client_label.keyword'; type = 'string'; esTypes = @('keyword'); scripted = $false; searchable = $true; aggregatable = $true; readFromDocValues = $true; subType = @{ multi = @{ parent = 'demo.client_label' } }
    }

    $indexPattern.attributes.fields = (To-CompactJson @($fields) 50)
}

$dashboard = $objects | Where-Object { $_.type -eq 'dashboard' -and $_.id -eq $dashboardId } | Select-Object -First 1
if (-not $dashboard) {
    throw "Dashboard not found in NDJSON: $dashboardId"
}

$dashboard.attributes.title = 'WebAuthGuard Security Overview'
$panels = New-Object System.Collections.ArrayList
($dashboard.attributes.panelsJSON | ConvertFrom-Json) | ForEach-Object { [void]$panels.Add($_) }

$refs = New-Object System.Collections.ArrayList
$dashboard.references | ForEach-Object { [void]$refs.Add($_) }

Ensure-Reference -References $refs -Name 'panel_13' -Type 'visualization' -Id 'wac-vis-top-targeted-accounts'
Ensure-Reference -References $refs -Name 'panel_14' -Type 'visualization' -Id 'wac-vis-threat-type-distribution'
Ensure-Reference -References $refs -Name 'panel_15' -Type 'visualization' -Id 'wac-vis-credential-stuffing-count'
Ensure-Reference -References $refs -Name 'panel_16' -Type 'visualization' -Id 'wac-vis-distributed-attack-count'
Ensure-Reference -References $refs -Name 'panel_17' -Type 'search' -Id 'wac-search-auth-log-monitor'

Ensure-Panel -Panels $panels -PanelRefName 'panel_13' -Type 'visualization' -PanelIndex '13' -Grid @{ x = 0; y = 62; w = 16; h = 10; i = '13' }
Ensure-Panel -Panels $panels -PanelRefName 'panel_14' -Type 'visualization' -PanelIndex '14' -Grid @{ x = 16; y = 62; w = 16; h = 10; i = '14' }
Ensure-Panel -Panels $panels -PanelRefName 'panel_15' -Type 'visualization' -PanelIndex '15' -Grid @{ x = 32; y = 62; w = 16; h = 10; i = '15' }
Ensure-Panel -Panels $panels -PanelRefName 'panel_16' -Type 'visualization' -PanelIndex '16' -Grid @{ x = 0; y = 72; w = 16; h = 10; i = '16' }
Ensure-Panel -Panels $panels -PanelRefName 'panel_17' -Type 'search' -PanelIndex '17' -Grid @{ x = 16; y = 72; w = 32; h = 16; i = '17' }

$dashboard.references = @($refs)
$dashboard.attributes.panelsJSON = (To-CompactJson @($panels) 40)

$lines = $objects | ForEach-Object { To-CompactJson $_ 120 }
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines((Resolve-Path $ndjsonPath), $lines, $utf8NoBom)

Write-Host "NDJSON upgraded with showcase panels and auth log monitor search."
