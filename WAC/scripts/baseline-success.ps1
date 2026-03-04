param(
    [string]$BaseUrl = "http://localhost:8000",
    [string]$RunId = ("run-baseline-" + (Get-Date -Format "yyyyMMdd-HHmmss")),
    [string]$TargetUser = "admin",
    [string]$WrongPassword = "Wrong123!"
)

$runner = Join-Path $PSScriptRoot 'run-attack-storyboard.ps1'
& $runner -BaseUrl $BaseUrl -RunId $RunId -TargetUser $TargetUser -WrongPassword $WrongPassword -Scenario "baseline_success"
