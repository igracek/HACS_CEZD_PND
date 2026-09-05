# ČEZ Distribuce PND - HACS Home Assistant Integrace

[![HACS Custom](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/default)
[![Home Assistant](https://img.shields.io/badge/Home%20Assistant-2026.8%2B-blue.svg)](https://home-assistant.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Nativní HACS integrace pro Home Assistant (vyvinuto pro **Home Assistant 2026.8 a novější**) pro automatické stahování 15minutových a denních naměřených dat z **Portálu Naměřených Dat ČEZ Distribuce (PND)** a jejich přímou integraci do **Home Assistant Energy Dashboardu** formou externích dlouhodobých statistik.

---

## ⚡ Hlavní funkce

- **Plná podpora Home Assistant Energy Dashboardu (HA 2026.8+):** 15minutové historické profily spotřeby (+A) a dodávky/výroby (-A) jsou importovány přes moderní API `async_add_external_statistics` do externích dlouhodobých statistik (`cez_pnd:<ean>_*`) s hodinovou UTC agregací a monotónně rostoucími kumulativními součty (`sum`).
- **Podpora sestav 01 (+A), 02 (-A), 08 (-A) a 17 (+E, -E):** Automatické stahování a parsování 15minutových profilů `01 Profil spotřeby (+A)` a `02 Profil výroby (-A)` (s fallbackem na `07` a `08`), denních souhrnů a podpora sestavy `17 Registry za den (+E, -E)` pro kontrolu a kalibraci tarifních registrů VT/NT.
- **Robustní podpora pro čistě odběrná místa i FVE:** Plná tolerance pro odběrná místa bez fotovoltaiky (výroba se automaticky nastaví na 0.0 kWh bez chybových stavů synchronizace).
- **Přepočet výkonu na energii a filtrace budoucích dat:** Automatická detekce a přepočet středního výkonu v `[kW]` na energii v `kWh` (faktor $0.25\,\text{h}$ pro 15min intervaly), validace profilů (+A vs -A) a filtrace nenaměřených budoucích dnů (`"neznámá hodnota"`).
- **Automatické rozlišení VT a NT (Vysoký / Nízký tarif):** Možnost napojení na libovolnou boolean entitu v HA (např. spínání HDO) – integrace zpětně rozdělí spotřebu podle stavu entity v daných intervalech (s bezpečným fallbackem na VT).
- **Konfigurace přes UI (Config Flow, Options Flow & Reauth):** Žádné ruční úpravy YAML souborů. Možnost správy více odběrných míst (EAN/ELM) v rámci jedné instalace, bezpečné rotace hesel bez prefillu a ochrana neměnnosti EAN.
- **Plná podpora ČEZ Single Sign-On:** Podpora SSO domén ČEZ (`pnd.cezdistribuce.cz`, `mepas.cez.cz`, `dip.cezdistribuce.cz`) s přísnou kontrolou originu.
- **Robustní diagnostický a debugovací subsystém:** Integrovaná nativní platforma diagnostiky Home Assistantu (`diagnostics.py`), opt-in ukládání sanitizovaných DOM HTML dumpů při chybách se striktní anonymizací (redaction) citlivých údajů a auto-pruningem.
- **Bezpečnostní architektura a správa procesů:** Běh headless prohlížeče v HA Executor thread poolu pod dohledem procesního semaforu, garance uvolnění zdrojů, okamžitá validace TLS originu na všech citlivých hranicích a explicitní rollback platforem při selhání setupu.
- **Striktní integrita a validace dat:** Diskrétní stavové senzory nemají `state_class: total` (zamezení zdvojení statistik v Recorderu), striktní odmítání neplatných hodnot a deterministický výpočet baseline sumy.

---

## 📦 Instalace a nastavení

### 1. Požadavky na systém a závislosti

> [!IMPORTANT]
> **Integrace sama webový prohlížeč neinstaluje.** Pro fungování automatizovaného stahování dat z portálu ČEZ PND je nutné mít v prostředí Home Assistantu nebo na hostitelském operačním systému externě nainstalován podporovaný webový prohlížeč a odpovídající webdriver.

Pro spolehlivý běh integrace jsou vyžadovány následující verze komponent a runtime závislostí:

- **Home Assistant Core:** `2026.8.0+`
- **Python:** `3.12+` / `3.14+`
- **Python knihovny (spravováno v manifest.json):**
  - `selenium>=4.15.0,<5.0.0`
  - `beautifulsoup4>=4.12.0,<5.0.0`
- **Podporované webové prohlížeče a ovladače:**
  - **Chromium / Google Chrome** a odpovídající **ChromeDriver** *(doporučeno)*
  - **Mozilla Firefox** a **Geckodriver**
- **Home Assistant OS / Supervised / Container (Alpine Linux):**
  - V prostředí kontejneru Home Assistantu nainstalujte balíčky Chromium:
    ```bash
    apk add --no-cache chromium chromium-chromedriver su-exec
    ```
- **Home Assistant Core / Vlastní Linux (Debian, Ubuntu apod.):**
  - Na hostitelském systému nainstalujte balíčky Chromium nebo Firefox:
    ```bash
    sudo apt update && sudo apt install -y chromium-browser chromium-chromedriver
    # nebo pro Firefox:
    # sudo apt install -y firefox-esr geckodriver
    ```

### 2. Instalace přes HACS (Vlastní repozitář na GitHubu)

Integraci lze přidat do HACS jako vlastní repozitář:

1. V Home Assistantu přejděte do **HACS** -> v pravém horním rohu klikněte na **tři tečky (⋮)** -> zvolte **Uživatelské repozitáře** (*Custom repositories*).
2. Do pole **Repozitář** (*Repository*) vložte URL adresu repozitáře na GitHubu:
   ```text
   https://github.com/igracek/HACS_CEZD_PND
   ```
3. V poli **Kategorie** (*Category*) vyberte **Integrace** (*Integration*).
4. Klikněte na **Přidat** (*Add*).
5. V HACS vyhledejte **ČEZ Distribuce PND** a klikněte na **Stáhnout** (*Download*).
6. Restartujte Home Assistant.

### 3. Manuální instalace (stažením z GitHubu / ZIP archivu)

1. Stáhněte nejnovější vydání (Release) nebo naklonujte repozitář z GitHubu:
   ```bash
   git clone https://github.com/igracek/HACS_CEZD_PND.git
   ```
2. Zkopírujte složku `custom_components/cez_pnd` do konfiguračního adresáře Home Assistantu:
   ```text
   /config/custom_components/cez_pnd/
   ```
   *(Pokud složka `custom_components` ve vašem `/config/` neexistuje, vytvořte ji).*
3. Restartujte Home Assistant.

### 4. Konfigurace integrace
1. Přejděte do **Nastavení** -> **Zařízení a služby** -> **Přidat integraci**.
2. Vyhledejte **ČEZ Distribuce PND**.
3. Vyplňte formulář:
   - **Uživatelské jméno / e-mail:** Přihlašovací e-mail k portálu ČEZ PND / SSO.
   - **Heslo:** Heslo k portálu ČEZ.
   - **EAN:** 18místný číselný kód odběrného místa (např. `859182400123456789`).
   - **Číslo elektroměru (ELM):** Číslo zobrazené v portálu ČEZ PND (výběr ze seznamu nebo zadání).
   - **Volitelná VT/NT entita:** Např. `binary_sensor.hdo_tarif` (ON = VT, OFF = NT). Pokud není zadána, vše se počítá jako VT.
   - **Čas denního stahování:** Výchozí `06:00`.
   - **Debug režim / Ladicí složka:** Volitelná aktivace rozšířeného debugování (ve výchozím stavu vypnuto) a volba cílové složky (`/config/cez_pnd_debug/`).

### 5. 🚀 Prvotní načtení historických dat (Backfilling)
Při prvotní instalaci integrace automaticky stáhne naměřená data za předchozí den (Den-1). Pokud si přejete do Home Assistant Energy Dashboardu načíst delší historii (např. 1 až 2 měsíce zpětně):
1. Přejděte do **Vývojářské nástroje** -> záložka **Akce / Služby** (Services).
2. Zvolte službu `cez_pnd.fetch_data` (**Stáhnout data z PND**).
3. Vyplňte pole **Období** (`date_range`) ve formátu `DD.MM.YYYY - DD.MM.YYYY` (např. `01.07.2026 - 31.08.2026`, bezpečnostní limit je max. 60 dní na jedno volání).
4. Pokud máte nakonfigurováno více odběrných míst, zadejte i cílový **EAN kód**.
5. Klikněte na **Provést akci**. Integrace z portálu ČEZ PND stáhne 15minutové profily spotřeby (+A) i výroby (-A), provede rozdělení VT/NT a automaticky naplní dlouhodobé statistiky v Energy Dashboardu se správným přepočtem kumulativních sum.

---

## 📊 Energy Dashboard konfigurace

> [!IMPORTANT]
> Do konfigurace panelu Energie **nikdy nepřidávejte diskrétní stavové senzory** `sensor.cez_elektromer_..._vcerejsi_spotreba` ani `..._intervalova_spotreba`. Tyto senzory slouží pouze pro okamžité zobrazení stavu a nemají `state_class: total`. V Energy Dashboardu vždy vyberte **externí dlouhodobé statistiky**:

1. **Spotřeba ze sítě (Odběr):**
   - Vysoký tarif (VT): `cez_pnd:<ean>_consumption_vt` (nebo celková spotřeba `cez_pnd:<ean>_consumption`)
   - Nízký tarif (NT): `cez_pnd:<ean>_consumption_nt`
2. **Dodávka do sítě (FVE přebytky / Výroba):**
   - Výroba / Dodávka: `cez_pnd:<ean>_production`

*Poznámka:* Data se v Energy Dashboardu zobrazují zpětně v přesných hodinových UTC intervalech odpovídajících reálnému času spotřeby/dodávky za předchozí dny, aniž by docházelo ke zkreslení aktuálního dne či kolizím s lokálními podružnými měřidly.

---

## 🏷️ Přehled poskytovaných entit

Všechny vytvořené entity jsou registrovány pod zařízením **ČEZ Elektroměr (maskovaný EAN)** v HA Device Registry:

| Entita | Typ | Popis |
| :--- | :--- | :--- |
| `sensor.cez_pnd_<ean>_yesterday_consumption` | Senzor | Celková včerejší spotřeba (kWh, diskrétní stav) |
| `sensor.cez_pnd_<ean>_yesterday_production` | Senzor | Celková včerejší výroba / dodávka do sítě (kWh, diskrétní stav) |
| `sensor.cez_pnd_<ean>_interval_consumption` | Senzor | Poslední naměřená 15min spotřeba (kWh, diskrétní stav) |
| `sensor.cez_pnd_<ean>_interval_production` | Senzor | Poslední naměřená 15min výroba (kWh, diskrétní stav) |
| `sensor.cez_pnd_<ean>_production_ratio` | Senzor | Poměr pokrytí spotřeby výrobou (%) |
| `sensor.cez_pnd_<ean>_app_version` | Senzor | Verze integrace a portálu PND |
| `sensor.cez_pnd_<ean>_sync_duration` | Senzor | Doba trvání poslední synchronizace (s) |
| `binary_sensor.cez_pnd_<ean>_running` | Binární senzor | Indikuje právě probíhající stahování dat |
| `binary_sensor.cez_pnd_<ean>_status` | Binární senzor | Stav integrace (OK / Chyba spojení či přihlášení) |

---

## 🔍 Diagnostika, ladění a řešení problémů

Integrace obsahuje ucelený systém pro odhalování a analýzu chyb:

### 1. Nativní Home Assistant Diagnostics
V **Nastavení -> Zařízení a služby -> ČEZ Distribuce PND** klikněte na tři tečky a zvolte **Stáhnout diagnostiku**.
Vygenerovaný JSON soubor obsahuje:
- Stav koordinátoru, čas poslední synchronizace a statistické metriky (sumy, čítače duplicit).
- Diagnostiku tarifu (počet načtených stavů z HA Recorderu, rozpad VT/NT v kWh a podíl VT v %).
- Informace o prostředí scraperu a reprodukovatelnou diagnostickou atestaci verzí (`selenium_version`, `beautifulsoup4_version`, `python_version`, přítomnost ovladačů).
- **Všechny citlivé údaje (hesla, tokeny, celé EAN a systémové či binární cesty) jsou striktně anonymizovány (redacted) bez úniku souborových cest.**

### 2. Opt-in záchyty chyb portálu PND (Error Dumps)
Při zapnutém ladicím režimu (`debug_mode: true`) a jakémkoliv selhání na webu ČEZ PND (CAPTCHA, zablokovaný účet, odstávka portálu, nenalezení ELM nebo chybějící tlačítko exportu) scraper vytvoří sadu ladicích souborů do složky `/config/cez_pnd_debug/`:
- `<timestamp>_error.png` – snímek obrazovky v okamžiku chyby (striktně zakázán po zadání přihlašovacích údajů).
- `<timestamp>_dom.html` – kompletní DOM strom stránky se sanitizovanými hesly, tokeny a skripty.
- `<timestamp>_meta.json` – metadata chyby (sanitizované chybové kódy `ERR_*`, maskovaný identifikátor ELM/EAN).

*Ladicí soubory mají bezpečnostní práva `0600` a staré snímky jsou automaticky promazávány (udržuje se max. 5 nejnovějších sad po dobu 7 dní).*

### 3. Povolení debug logování
V `configuration.yaml` přidejte:
```yaml
logger:
  default: info
  logs:
    custom_components.cez_pnd: debug
```

---

## 🛠️ Poskytované služby (Services)

- `cez_pnd.fetch_data`: Spustí okamžité stažení dat. Volitelný parametr `date_range` (např. `"01.08.2026 - 15.08.2026"`, max 60 dní) umožňuje zpětné dočtení historických dat (backfilling).

---

## 🔒 Bezpečnost a ochrana soukromí

Integrace klade maximální důraz na bezpečnost a integritu dat:
- **Žádné ukládání hesel v prostém textu do logů:** Veškeré přihlašovací údaje, tokeny a citlivé hodnoty jsou striktně sanitizovány (maskovány) před jakýmkoliv zápisem do systémových záznamů či diagnostických exportů.
- **Validace původu (Origin & Host validation):** Při komunikaci s portálem ČEZ PND a SSO (Single Sign-On) je striktně kontrolována legitimita domény a cesta před předáním autentizačních údajů.
- **Bezpečný běh prohlížeče:** Webový scraper běží v izolovaném kontextu pod dohledem procesního semaforu s garantovaným uvolněním prostředků a zamezením zombie procesů.
- **Integrita a validace stažených sestav:** Stažené CSV reporty procházejí strukturální a profilovou validací (+A spotřeba vs. -A výroba) pro zajištění správného naplnění dlouhodobých statistik.

---

## 📄 Licence

Tento projekt je licencován pod licencí MIT - viz soubor [LICENSE](LICENSE) pro podrobnosti.
