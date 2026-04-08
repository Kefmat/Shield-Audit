# Shield-Audit

**Automated Security Compliance & Hardening Tool**

Shield-Audit er et rammeverk utviklet for å automatisere revisjon og herding (hardening) av Windows-servere. Verktøyet går utover enkel monitorering ved å sammenligne systemets sanntidstilstand mot en definert "Gull-standard" (Policy-as-Code) og aktivt utbedre sikkerhetsavvik.

## 1. Funksjonalitet

Prosjektet har nådd MVP-status og inkluderer følgende kjernefunksjonalitet:

- **Identity & Privilege Audit:** Validerer administrative rettigheter mot hvitliste og identifiserer inaktive brukerkontoer (stale accounts).
- **Network Hardening:** Verifiserer status for Windows Firewall-profiler og kontrollerer at usikre funksjoner som gjestekontoer er deaktivert.
- **Auto-Remediation:** Inkluderer en beslutningsmotor som automatisk kan lukke sikkerhetshull (for eksempel reaktivere brannmur) dersom policyen tillater det.
- **Security Scoring:** Beregner en total Security Score (0-100) basert på vektede funn, som gir en umiddelbar indikasjon på systemets compliance-status.
- **Structured Reporting:** Genererer detaljerte rapporter i JSON-format for integrasjon i SIEM-systemer eller dashboards.

## 2. Arkitektur

Systemet er bygget modulært for å sikre enkel utvidelse:

- `config/Policy.json`: Den sentrale kilden til sannhet som definerer tillatte administratorer og sikkerhetsinnstillinger.
- `src/ShieldAudit.ps1`: Hovedmotoren som benytter godkjente PowerShell-verb (Test-, Invoke-) for revisjon og utbedring.
- `reports/`: Database for revisjonshistorikk og compliance-dokumentasjon.

## 3. Tekniske valg

- **PowerShell Core:** Brukes for dyp systemintegrasjon og effektiv informasjonsinnhenting.
- **Policy-Driven Design:** Skiller konfigurasjon fra logikk, som gjør verktøyet skalerbart på tvers av ulike serverroller.
- **Desired State Logic:** Implementerer prinsipper fra moderne infrastrukturstyring der skriptet tvinger systemet tilbake til sikker tilstand.

## 4. Veien videre (Roadmap)

Prosjektet er i kontinuerlig utvikling, og følgende moduler er planlagt for neste fase:

- **Patch Management Module:** Integrasjon mot Windows Update for å verifisere at kritiske sikkerhetsoppdateringer er installert.
- **Audit-Log Analysis:** Skanning av systemlogger for å detektere brute force-forsøk eller uvanlig påloggingsaktivitet.
- **HTML Dashboard:** En visuell fremstilling av `reports/FullAuditReport.json` for enklere presentasjon for ledelsen.
- **Integrert overvåking:** Koble Shield-Audit sammen med PLM Guardian og NetPulse Observer for en komplett Admin Suite.

## 5. Bruk

1. Definer sikkerhetskrav i `config/Policy.json`.
2. Kjør revisjon med:

```powershell
.\src\ShieldAudit.ps1
```

3. Analyser resultatene i `reports/FullAuditReport.json`.

