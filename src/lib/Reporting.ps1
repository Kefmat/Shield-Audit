function New-ShieldHtmlReport {
    param($Data, $TotalScore, $Path)

    $StatusColor = if ($TotalScore -ge 80) { "#27ae60" } else { "#c0392b" }
    
    $HtmlHeader = @"
    <!DOCTYPE html>
    <html lang="no">
    <head>
        <meta charset="UTF-8">
        <title>Shield-Audit Security Report</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, sans-serif; background-color: #f4f7f6; margin: 40px; }
            .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); max-width: 1000px; margin: auto; }
            .score-box { background: $StatusColor; color: white; padding: 20px; border-radius: 5px; text-align: center; font-size: 28px; margin-bottom: 25px; }
            .module-card { border-left: 5px solid #3498db; background: #fafafa; margin: 15px 0; padding: 20px; border-radius: 0 5px 5px 0; }
            .finding { color: #e67e22; font-weight: bold; list-style-type: '⚠ '; }
            h1 { color: #2c3e50; }
            .footer { margin-top: 30px; font-size: 12px; color: #95a5a6; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Shield-Audit v1.6 Report</h1>
            <div class="score-box">Total Security Score: $TotalScore / 100</div>
            <p><strong>Dato:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>
            <p><strong>Maskinnavn:</strong> $($env:COMPUTERNAME)</p>
            <hr>
"@

    $HtmlBody = foreach ($Mod in $Data) {
        $FindingsHtml = if ($Mod.Findings) { 
            ($Mod.Findings | ForEach-Object { "<li class='finding'>$_</li>" }) -join "" 
        } else { "<li>Systemet er i samsvar med policy i denne modulen.</li>" }
        
        @"
        <div class="module-card">
            <h3>Modul: $($Mod.Module) - Score: $($Mod.Score)</h3>
            <ul>$FindingsHtml</ul>
        </div>
"@
    }

    $HtmlFooter = @"
            <div class="footer">Rapporten er generert automatisk av Shield-Audit Framework.</div>
        </div>
    </body>
    </html>
"@

    $HtmlHeader + ($HtmlBody -join "") + $HtmlFooter | Out-File $Path -Encoding utf8
    Write-Host "`n[VISUAL] HTML-rapport er nå klar i /reports/" -ForegroundColor Green
}