<#
.SYNOPSIS
    Shield-Audit - Security Compliance & Auto-Remediation.
.DESCRIPTION
    Reviderer Windows-servere og kan automatisk utbedre sikkerhetsavvik 
    basert på definert policy (Auto-Remediation).
.NOTES
    Oppdatert med godkjente verb (Test-) og rettet feil i parameterliste.
#>

$ConfigPath = "$PSScriptRoot\..\config\Policy.json"
$ReportDir = "$PSScriptRoot\..\reports"

# Initialisering av miljø og konfigurasjon
if (!(Test-Path $ConfigPath)) { 
    Write-Host "CRITICAL: Konfigurasjonsfil mangler!" -ForegroundColor Red
    exit 
}
$Policy = Get-Content $ConfigPath | ConvertFrom-Json

# Sikrer at nødvendige mapper eksisterer
if (!(Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force }

<#
.SYNOPSIS
    Utfører automatiske utbedringer basert på audit-funn.
.DESCRIPTION
    Sjekker om AutoRemediate er aktivert i policy og fikser spesifiserte avvik.
#>
function Invoke-Remediation {
    param([string]$Type, [string]$Detail)
    
    if ($Policy.NetworkPolicy.AutoRemediate -eq $true) {
        Write-Host " [REMEDIATION] Forsøker automatisk utbedring: $Type" -ForegroundColor Magenta
        
        switch ($Type) {
            "FIREWALL" {
                Set-NetFirewallProfile -All -Enabled True
                return "SUCCESS: Alle brannmurprofiler er nå aktivert."
            }
            "GUEST_ACCOUNT" {
                Disable-LocalUser -Name "Guest"
                return "SUCCESS: Gjestekonto er nå deaktivert."
            }
        }
    }
    return "PENDING: Ingen automatisk endring utført (AutoRemediate er AV)."
}

<#
.SYNOPSIS
    Tester identiteter og administrative privilegier.
#>
function Test-ShieldIdentity {
    $Findings = @()
    $Score = 100
    Write-Host "`n[1] Analyserer Identiteter og Tilgang..." -ForegroundColor Cyan

    # A. Sjekk Administrator-privilegier
    $CurrentAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
    foreach ($Admin in $CurrentAdmins) {
        if ($Policy.IdentityPolicy.AllowedAdmins -notcontains $Admin) {
            $Findings += "UNAUTHORIZED ADMIN: Brukeren '$Admin' har admin-rettigheter, men er ikke i hvitlisten."
            $Score -= 20
        }
    }

    # B. Sjekk for Inaktive Brukere (Stale Accounts)
    $LimitDate = (Get-Date).AddDays(-$Policy.IdentityPolicy.MaxInactiveDays)
    $AllUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    
    foreach ($User in $AllUsers) {
        if ($null -ne $User.LastLogon) {
            if ($User.LastLogon -lt $LimitDate) {
                $Findings += "STALE ACCOUNT: '$($User.Name)' har ikke logget inn siden $($User.LastLogon). Risiko for misbruk."
                $Score -= 10
            }
        }
    }

    return [PSCustomObject]@{ 
        Module = "Identity" 
        Score = [Math]::Max(0, $Score) 
        Findings = $Findings 
    }
}

<#
.SYNOPSIS
    Tester nettverksharding og utfører utbedring hvis aktivert.
#>
function Test-ShieldNetwork {
    $Findings = @()
    $Remediations = @()
    $Score = 100
    Write-Host "[2] Analyserer Nettverksharding & Gjestetilgang..." -ForegroundColor Cyan

    # Brannmur-sjekk med potensiell utbedring
    $Profiles = Get-NetFirewallProfile
    if ($Policy.NetworkPolicy.FirewallRequired -and ($Profiles.Enabled -contains "False")) {
        $Findings += "FIREWALL: Profiler deaktivert."
        $Score -= 40
        $Remediations += Invoke-Remediation -Type "FIREWALL"
    }

    # Gjestekonto-sjekk med potensiell utbedring
    if ($Policy.NetworkPolicy.BlockGuestAccess) {
        $GuestUser = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($GuestUser -and $GuestUser.Enabled) {
            $Findings += "SECURITY RISK: Gjestekonto aktivert."
            $Score -= 20
            $Remediations += Invoke-Remediation -Type "GUEST_ACCOUNT"
        }
    }

    return [PSCustomObject]@{ 
        Module = "Network"
        Score = [Math]::Max(0, $Score)
        Findings = $Findings
        Remediations = $Remediations 
    }
}

# --- Hovedløp ---

# Kjører moduler og beregner totalscore
$ModuleResults = @((Test-ShieldIdentity), (Test-ShieldNetwork))
$TotalScore = [Math]::Round(($ModuleResults.Score | Measure-Object -Average).Average, 0)

Write-Host "-------------------------------------------"
Write-Host "SHIELD-AUDIT FULLFØRT: $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
Write-Host "TOTAL SECURITY SCORE: $TotalScore / 100" -ForegroundColor (if($TotalScore -ge 80){"Green"}else{"Red"})

# Rapport-generering
$FullReport = [PSCustomObject]@{
    Timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm"
    TotalScore = $TotalScore
    AutoRemediateEnabled = $Policy.NetworkPolicy.AutoRemediate
    Modules    = $ModuleResults
}
$FullReport | ConvertTo-Json -Depth 4 | Out-File "$ReportDir\FullAuditReport.json" -Encoding utf8

# Oppsummering av funn og status (Rettet feil i filtreringslogikk)
$FlattenedFindings = $ModuleResults.Findings | Where-Object { $null -ne $_ }

if ($FlattenedFindings.Count -gt 0) {
    Write-Host "`nFUNN OG STATUS:" -ForegroundColor Red
    $ModuleResults | ForEach-Object {
        $_.Findings | ForEach-Object { Write-Host " [!] $_" -ForegroundColor Yellow }
        $_.Remediations | ForEach-Object { Write-Host " [>] $_" -ForegroundColor Magenta }
    }
} else {
    Write-Host "`nSystemet er i samsvar med policy." -ForegroundColor Green
}