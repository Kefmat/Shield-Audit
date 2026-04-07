# Shield-Audit

Status: Planleggingsfase

Shield-Audit er planlagt som et verktøy for å kontrollere sikkerhetsstatus og etterlevelse på Windows-servere. Målet er å gjøre revisjon enklere, mer konsistent og lettere å følge opp over tid.

## Formål

Prosjektet skal gjøre det mulig å:

- sammenligne en server mot en definert sikkerhetspolicy
- finne avvik i konfigurasjon, tilgang og oppdateringsstatus
- generere en rapport som kan brukes videre i drift, revisjon og dokumentasjon

## Problem som skal løses

Manuelle sikkerhetssjekker tar tid, er lette å gjøre ulikt fra gang til gang og gir dårlig sporbarhet. Prosjektet er ment å redusere dette ved å samle kontroller i ett verktøy.

Eksempler på spørsmål verktøyet skal kunne svare på:

- Hvem har administrative rettigheter nå?
- Har serveren avvik fra forventede brannmurregler?
- Mangler systemet viktige oppdateringer?
- Finnes det gamle eller inaktive kontoer med tilgang?

## Foreløpig scope

Første versjon er tenkt å dekke:

- identitet og gruppemedlemskap
- administrative rettigheter
- brannmur og nettverksrelaterte innstillinger
- patch- og oppdateringsstatus
- enkel scoring eller oppsummering av funn

## Foreløpig arkitektur

Prosjektet er planlagt med disse hoveddelene:

- Policy-fil: beskriver ønsket tilstand og godkjente unntak
- Innsamling: henter relevant systeminformasjon fra Windows
- Analyse: sammenligner innsamlede data med policy
- Rapportering: skriver resultat til et strukturert format, for eksempel JSON

## Teknologivalg så langt

- PowerShell for innsamling og systemkontroller
- JSON for policy og rapportdata

## Neste steg

- definere første policy-format
- avgrense hvilke kontroller som skal inn i MVP
- lage enkel mappe- og prosjektstruktur
- implementere første innsamlingsskript
- lage første rapportformat

## MVP-idé

En første brukbar versjon kan være et script som:

1. leser en enkel policy fra JSON
2. henter lokal sikkerhetsinformasjon fra en Windows-server
3. sammenligner funn mot policy
4. skriver en kort rapport med avvik

## Mål

Målet i denne fasen er å planlegge et lite, tydelig og utvidbart verktøy før implementasjon starter.