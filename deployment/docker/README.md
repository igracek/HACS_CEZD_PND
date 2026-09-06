# Bezpečná runtime konfigurace kontejneru pro Chromium (SEC10-03 / CWE-693 / CWE-250)

Tento dokument a doprovodné konfigurační soubory definují standard bezpečného nasazení integrační komponenty `cez_pnd` v kontejnerových prostředích Home Assistantu (Docker, Supervised, Container).

## 1. Bezpečnostní politika sandboxu

1. **Striktní zákaz vypínání sandboxu:**
   V integračním kódu i v produkčním kontejnerovém prostředí je zakázáno používat volby oslabující sandbox:
   - `--no-sandbox`
   - `--disable-seccomp-filter-sandbox`
   - `--disable-setuid-sandbox`

2. **Odstranění dřívějšího provizorního workaroundu:**
   V kroku 112 byl v kontejneru dočasně nasazen soubor `/etc/chromium/docker.conf` s volbou `--disable-seccomp-filter-sandbox`. Tento workaround je tímto **zrušen a zakázán**. Komponenta `cez_pnd` aktivně validuje efektivní příkazový řádek a přítomnost zakázaných voleb v prostředí a při jejich detekci okamžitě selhává s chybou `ERR_INSECURE_BROWSER`.

## 2. Doporučená konfigurace Docker démona a kontejneru

Aby Chromium headless běželo stabilně pod neprivilegovaným uživatelem (`nobody` / `chrome`) se všemi vrstvami sandboxu (včetně seccomp-bpf filtru):

- **Moderní Docker (20.10+):**
  Výchozí seccomp profil Dockeru již plně podporuje systémová volání potřebná pro Chromium sandbox (`clone`, `clone3`, `seccomp`). Ujistěte se, že kontejner nepoužívá restriktivní zastaralý profil blokující `seccomp(2)`.

- **Spuštění kontejneru Home Assistantu:**
  Při běhu v Dockeru se doporučuje spustit kontejner se standardním seccomp profilem:
  ```yaml
  services:
    homeassistant:
      image: ghcr.io/home-assistant/home-assistant:stable
      security_opt:
        - seccomp=unconfined # nebo výchozí seccomp profil s povoleným seccomp-bpf
  ```

- **Runtime konfigurační soubor `/etc/chromium/docker.conf`:**
  Použijte přiložený soubor `deployment/docker/chromium-runtime.conf`:
  ```bash
  cp deployment/docker/chromium-runtime.conf /etc/chromium/docker.conf
  ```
  Tento soubor nastavuje prázdné `CHROMIUM_FLAGS=""`, což zajišťuje, že se nespustí žádné přepínače vypínající seccomp nebo procesní sandbox.

## 3. Diagnostická atestace

Komponenta automaticky zahrnuje kontrolu sandboxu v diagnostickém výstupu (`diagnostics.py`):
- `seccomp_filter_sandbox_enforced: true`
- `disallowed_flags_detected: []`
- `effective_sandbox_mode: "enforced_least_privilege"`
