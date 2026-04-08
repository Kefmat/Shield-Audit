<#
.SYNOPSIS
    Shield-Audit v1.4 - Comprehensive Security & System Compliance.
.DESCRIPTION
    Reviderer Windows-servere og kan automatisk utbedre sikkerhetsavvik 
    basert på definert policy (Auto-Remediation). Inkluderer nå kontroll
    av systemhelse og oppdateringsstatus (Patch Management).
.NOTES
    Oppdatert med godkjente verb (Test-) og utvidet systemanalyse.
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
.DESCRIPTION
    Sammenligner lokale administratorer mot en hvitliste og finner inaktive kontoer.
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
.DESCRIPTION
    Verifiserer status på brannmurprofiler og sjekker om gjestekontoen er deaktivert.
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

<#
.SYNOPSIS
    Tester systemhelse og patch-status.
.DESCRIPTION
    Sjekker ledig diskplass og verifiserer når systemet sist ble oppdatert.
#>
function Test-ShieldSystem {
    $Findings = @()
    $Score = 100
    Write-Host "[3] Analyserer System & Patch Compliance..." -ForegroundColor Cyan

    # A. Sjekk Diskplass (Kritisk for patching og stabilitet)
    $Drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $FreeGB = [Math]::Round($Drive.FreeSpace / 1GB, 2)
    if ($FreeGB -lt $Policy.SystemPolicy.MinFreeDiskGB) {
        $Findings += "STORAGE: Lav diskplass ($FreeGB GB). Kravet er $($Policy.SystemPolicy.MinFreeDiskGB) GB."
        $Score -= 20
    }

    # B. Sjekk Windows Update historikk via COM API
    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $HistoryCount = $UpdateSearcher.GetTotalHistoryCount()
        
        if ($HistoryCount -eq 0) {
            $Findings += "PATCH: Ingen oppdateringshistorikk funnet på systemet."
            $Score -= 30
        } else {
            $LastUpdate = $UpdateSearcher.QueryHistory(0, 1) | Select-Object -ExpandProperty Date
            $DaysSince = ((Get-Date) - $LastUpdate).Days
            if ($DaysSince -gt $Policy.SystemPolicy.MaxDaysSinceLastUpdate) {
                $Findings += "PATCH: Systemet har ikke blitt oppdatert på $DaysSince dager."
                $Score -= 25
            }
        }
    } catch {
        $Findings += "ERROR: Kunne ikke koble til Windows Update API for verifisering."
    }

    return [PSCustomObject]@{ 
        Module = "System" 
        Score = [Math]::Max(0, $Score) 
        Findings = $Findings 
    }
}

# --- Hovedløp ---

# Kjører moduler og beregner totalscore (Bruker semikolon for konsistens)
$ModuleResults = @(Test-ShieldIdentity; Test-ShieldNetwork; Test-ShieldSystem)
$TotalScore = [Math]::Round(($ModuleResults.Score | Measure-Object -Average).Average, 0)

# Terminal-output for umiddelbar oversikt
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

# Oppsummering av funn og status
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