<#
.SYNOPSIS
    Shield-Audit - Identity & Privilege Module
.DESCRIPTION
    Sjekker lokale administratorer og inaktive brukerkontoer mot definert policy.
#>

$ConfigPath = "$PSScriptRoot\..\config\Policy.json"
$ReportDir = "$PSScriptRoot\..\reports"

# Laster inn Policy
if (!(Test-Path $ConfigPath)) { 
    Write-Host "FEIL: Fant ikke Policy.json" -ForegroundColor Red
    exit 
}
$Policy = Get-Content $ConfigPath | ConvertFrom-Json
if (!(Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force }

# Funksjon for Identitets-Audit
function Audit-Identities {
    $Findings = @()
    $SecurityScore = 100

    Write-Host "`n[1] Starter Identitets- og Tilgangsrevisjon..." -ForegroundColor Cyan

    # A. Sjekk Administrator-privilegier
    $CurrentAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
    foreach ($Admin in $CurrentAdmins) {
        if ($Policy.IdentityPolicy.AllowedAdmins -notcontains $Admin) {
            $Findings += "UNAUTHORIZED ADMIN: Brukeren '$Admin' har admin-rettigheter, men er ikke i hvitlisten."
            $SecurityScore -= 20
        }
    }

    # B. Sjekk for Inaktive Brukere (Stale Accounts)
    $LimitDate = (Get-Date).AddDays(-$Policy.IdentityPolicy.MaxInactiveDays)
    $AllUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    
    foreach ($User in $AllUsers) {
        # Noen brukere har aldri logget inn, sjekk for $null
        if ($null -ne $User.LastLogon) {
            if ($User.LastLogon -lt $LimitDate) {
                $Findings += "STALE ACCOUNT: '$($User.Name)' har ikke logget inn siden $($User.LastLogon). Risiko for misbruk."
                $SecurityScore -= 10
            }
        }
    }

    return [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
        Module    = "Identity & Privileges"
        Score     = [Math]::Max(0, $SecurityScore)
        Findings  = $Findings
    }
}

# Kjører Audit og lagre rapport
$Result = Audit-Identities

# Output til terminal
Write-Host "-------------------------------------------"
Write-Host "AUDIT FULLFØRT: $($Result.Timestamp)" -ForegroundColor White
Write-Host "SECURITY SCORE: $($Result.Score) / 100" -ForegroundColor (if($Result.Score -ge 80){"Green"}else{"Yellow"})

if ($Result.Findings.Count -gt 0) {
    Write-Host "`nFUNN SOM KREVER TILTAK:" -ForegroundColor Red
    $Result.Findings | ForEach-Object { Write-Host " [!] $_" -ForegroundColor Yellow }
} else {
    Write-Host "`nIngen kritiske avvik funnet i denne modulen." -ForegroundColor Green
}

# Lagre til JSON-rapport
$Result | ConvertTo-Json | Out-File "$ReportDir\IdentityAudit.json" -Encoding utf8