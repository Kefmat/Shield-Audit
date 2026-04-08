<#
.SYNOPSIS
    Sikkerhetsmoduler for Shield-Audit.
.DESCRIPTION
    Inneholder alle test-funksjoner for identitet, nettverk, system og integritet.
    Bruker Global:Policy for konfigurasjonsverdier.
#>

function Test-ShieldIdentity {
    $Findings = @(); $Score = 100
    Write-Host "`n[1] Analyserer Identiteter og Tilgang..." -ForegroundColor Cyan

    try {
        # Sjekk Administrator-privilegier
        $CurrentAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Select-Object -ExpandProperty Name
        foreach ($Admin in $CurrentAdmins) {
            if ($Global:Policy.IdentityPolicy.AllowedAdmins -notcontains $Admin) {
                $Findings += "UNAUTHORIZED ADMIN: Brukeren '$Admin' har admin-rettigheter, men er ikke i hvitlisten."
                $Score -= 20
            }
        }

        # Sjekk for Inaktive Brukere (Stale Accounts)
        $LimitDate = (Get-Date).AddDays(-$Global:Policy.IdentityPolicy.MaxInactiveDays)
        $AllUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
        foreach ($User in $AllUsers) {
            if ($null -ne $User.LastLogon -and $User.LastLogon -lt $LimitDate) {
                $Findings += "STALE ACCOUNT: '$($User.Name)' har ikke logget inn siden $($User.LastLogon). Risiko for misbruk."
                $Score -= 10
            }
        }
    } catch {
        $Findings += "ERROR: Kunne ikke fullføre identitetsanalyse ($($_.Exception.Message))."
        $Score = 0
    }
    
    return [PSCustomObject]@{ Module = "Identity"; Score = [Math]::Max(0, $Score); Findings = $Findings }
}

function Test-ShieldNetwork {
    $Findings = @(); $Remediations = @(); $Score = 100
    Write-Host "[2] Analyserer Nettverksharding & Gjestetilgang..." -ForegroundColor Cyan

    try {
        # Brannmur-sjekk
        $Profiles = Get-NetFirewallProfile -ErrorAction Stop
        if ($Global:Policy.NetworkPolicy.FirewallRequired -and ($Profiles.Enabled -contains "False")) {
            $Findings += "FIREWALL: Profiler deaktivert."
            $Score -= 40
            $Remediations += Invoke-Remediation -Type "FIREWALL"
        }

        # Gjestekonto-sjekk
        if ($Global:Policy.NetworkPolicy.BlockGuestAccess) {
            $GuestUser = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
            if ($GuestUser -and $GuestUser.Enabled) {
                $Findings += "SECURITY RISK: Gjestekonto aktivert."
                $Score -= 20
                $Remediations += Invoke-Remediation -Type "GUEST_ACCOUNT"
            }
        }
    } catch {
        $Findings += "ERROR: Kunne ikke verifisere nettverksinnstillinger."
        $Score = 0
    }
    
    return [PSCustomObject]@{ Module = "Network"; Score = [Math]::Max(0, $Score); Findings = $Findings; Remediations = $Remediations }
}

function Test-ShieldSystem {
    $Findings = @(); $Score = 100
    Write-Host "[3] Analyserer System & Patch Compliance..." -ForegroundColor Cyan

    try {
        # Sjekk Diskplass
        $Drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
        $FreeGB = [Math]::Round($Drive.FreeSpace / 1GB, 2)
        if ($FreeGB -lt $Global:Policy.SystemPolicy.MinFreeDiskGB) {
            $Findings += "STORAGE: Lav diskplass ($FreeGB GB). Kravet er $($Global:Policy.SystemPolicy.MinFreeDiskGB) GB."
            $Score -= 20
        }

        # Sjekk Windows Update historikk
        $UpdateSearcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $HistoryCount = $UpdateSearcher.GetTotalHistoryCount()
        if ($HistoryCount -eq 0) {
            $Findings += "PATCH: Ingen oppdateringshistorikk funnet på systemet."
            $Score -= 30
        } else {
            $LastUpdate = $UpdateSearcher.QueryHistory(0, 1) | Select-Object -ExpandProperty Date
            $DaysSince = ((Get-Date) - $LastUpdate).Days
            if ($DaysSince -gt $Global:Policy.SystemPolicy.MaxDaysSinceLastUpdate) {
                $Findings += "PATCH: Systemet har ikke blitt oppdatert på $DaysSince dager."
                $Score -= 25
            }
        }
    } catch {
        $Findings += "ERROR: Feil ved sjekk av systemhelse/patching."
    }
    
    return [PSCustomObject]@{ Module = "System"; Score = [Math]::Max(0, $Score); Findings = $Findings }
}

function Test-ShieldIntegrity {
    $Findings = @(); $Score = 100
    Write-Host "[4] Analyserer Systemintegritet og Prosesser..." -ForegroundColor Cyan

    try {
        # Sjekk etter svartelistede prosesser
        $RunningProcesses = Get-Process | Select-Object -ExpandProperty Name
        foreach ($PName in $Global:Policy.SystemPolicy.BlacklistedProcesses) {
            if ($RunningProcesses -contains $PName) {
                $Findings += "SECURITY RISK: Svartelistet prosess kjører: '$PName'."
                $Score -= 25
            }
        }

        # Sjekk størrelse på Security Event Log
        $Log = Get-WinEvent -ListLog "Security" -ErrorAction Stop
        $LogSizeMB = [Math]::Round($Log.MaximumSizeInBytes / 1MB, 0)
        if ($LogSizeMB -lt $Global:Policy.SystemPolicy.MinSecurityLogSizeMB) {
            $Findings += "LOGGING: Security Log er for liten ($LogSizeMB MB). Kravet er $($Global:Policy.SystemPolicy.MinSecurityLogSizeMB) MB."
            $Score -= 15
        }
    } catch {
        $Findings += "ERROR: Kunne ikke lese sikkerhetslogger (krever admin-rettigheter)."
    }
    
    return [PSCustomObject]@{ Module = "Integrity"; Score = [Math]::Max(0, $Score); Findings = $Findings }
}