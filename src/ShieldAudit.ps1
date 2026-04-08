<#
.SYNOPSIS
    Shield-Audit - Enterprise Security Compliance & Integrity.
.DESCRIPTION
    Hovedmotor for Shield-Audit. Laster moduler, verifiserer rettigheter 
    og utfører full sikkerhetsrevisjon.
#>

# --- [ Administrator-sjekk ] ---
# Verifiserer at skriptet har nødvendige rettigheter for å lese sikkerhetslogger og endre systeminnstillinger.
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    Write-Host "FEIL: Shield-Audit må kjøres som Administrator." -ForegroundColor Red
    Write-Host "Vennligst start PowerShell som Administrator og prøv igjen." -ForegroundColor Red
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    exit
}

# --- [ Import og Oppsett ] ---
# Importerer under-moduler (Dot Sourcing)
. "$PSScriptRoot\Lib\SecurityTests.ps1"
. "$PSScriptRoot\Lib\Reporting.ps1"

$ConfigPath = "$PSScriptRoot\..\config\Policy.json"
$ReportDir = "$PSScriptRoot\..\reports"

# Initialisering av konfigurasjon
if (!(Test-Path $ConfigPath)) { 
    Write-Host "CRITICAL: Konfigurasjonsfil (Policy.json) mangler!" -ForegroundColor Red
    exit 
}
$Global:Policy = Get-Content $ConfigPath | ConvertFrom-Json

# Sikrer at rapportmappen eksisterer
if (!(Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force }

<#
.SYNOPSIS
    Utfører automatiske utbedringer basert på audit-funn.
#>
function Invoke-Remediation {
    param([string]$Type)
    if ($Global:Policy.NetworkPolicy.AutoRemediate -eq $true) {
        Write-Host " [REMEDIATION] Utfører utbedring: $Type" -ForegroundColor Magenta
        switch ($Type) {
            "FIREWALL" { Set-NetFirewallProfile -All -Enabled True; return "SUCCESS: Firewall aktivert." }
            "GUEST_ACCOUNT" { Disable-LocalUser -Name "Guest"; return "SUCCESS: Gjestekonto deaktivert." }
        }
    }
    return "PENDING: AutoRemediate er AV."
}

# --- [ Hovedløp ] ---

Write-Host "Shield-Audit starter full systemgjennomgang..." -ForegroundColor White

# Kjører alle moduler fra SecurityTests.ps1
$ModuleResults = @(
    (Test-ShieldIdentity); 
    (Test-ShieldNetwork); 
    (Test-ShieldSystem); 
    (Test-ShieldIntegrity)
)

# Beregner totalscore (gjennomsnitt av alle moduler)
$TotalScore = [Math]::Round(($ModuleResults.Score | Measure-Object -Average).Average, 0)

# --- [ Output og Rapportering ] ---

Write-Host "-------------------------------------------"
Write-Host "SHIELD-AUDIT FULLFØRT: $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
Write-Host "TOTAL SECURITY SCORE: $TotalScore / 100" -ForegroundColor (if($TotalScore -ge 80){"Green"}else{"Red"})

# Genererer JSON-data for historikk og dypdykk
$ModuleResults | ConvertTo-Json -Depth 4 | Out-File "$ReportDir\AuditData.json" -Encoding utf8

# Genererer den visuelle HTML-rapporten via Reporting.ps1
New-ShieldHtmlReport -Data $ModuleResults -TotalScore $TotalScore -Path "$ReportDir\ShieldReport.html"

# Oppsummering av funn i terminalen
$FlattenedFindings = $ModuleResults.Findings | Where-Object { $null -ne $_ }
if ($FlattenedFindings.Count -gt 0) {
    Write-Host "`nAVVIK FUNNET:" -ForegroundColor Yellow
    $FlattenedFindings | ForEach-Object { Write-Host " [!] $_" }
} else {
    Write-Host "`nSystemet er 100% compliant i henhold til policy." -ForegroundColor Green
}