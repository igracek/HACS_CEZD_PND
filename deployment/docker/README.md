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

## 2. Bezpečný výchozí profil Dockeru

Aby Chromium headless běželo stabilně pod neprivilegovaným uživatelem (`nobody` / `chrome`) se všemi vrstvami sandboxu (včetně seccomp-bpf filtru):

- **Moderní Docker (20.10+):**
  Použijte standardní profil Dockeru `docker-default`. Ten zůstává aktivní tím,
  že v Compose vůbec neuvedete `security_opt` override pro seccomp. Tento
  projekt nepodporuje běh bez kontejnerového seccomp profilu.

- **Spuštění kontejneru Home Assistantu:**
  Minimální bezpečnostní nastavení pro kontejner je:
  ```yaml
  services:
    homeassistant:
      image: ghcr.io/home-assistant/home-assistant:stable
      security_opt:
        - no-new-privileges:true
      privileged: false
      # Neuvádět seccomp override: Docker použije docker-default.
  ```
  Nepřidávejte capability a nepoužívejte privilegovaný režim. Chromium musí
  běžet pod neprivilegovaným účtem (`nobody` nebo `chrome`). Pokud hostitel
  vyžaduje vlastní seccomp profil, musí být minimálně ekvivalentní profilu
  `docker-default` a schválen mimo tento repozitář; jeho neověřená změna není
  bezpečná náhrada za výchozí profil.

  Kanonická deklarace této baseline je v
  `deployment/docker/container-security-policy.json`. Soubor popisuje
  požadovaný stav, není automatickým Docker override.

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

Před vydáním spusťte statický fail-closed gate:

```bash
python3 scripts/verify_container_sandbox.py
```

V běžícím kontejneru lze navíc ověřit bezpečnostní kontext kontrolovaného
procesu:

- všechny čtyři UID (`Uid`) musí být nenulové (ne-root),
- `NoNewPrivs: 1`,
- `CapEff`, `CapPrm` i `CapAmb` musí být nulové,
- `Seccomp: 2` a `Seccomp_filters >= 1`.

Pro kontrolu samotného procesu, ve kterém checker běží, spusťte:

```bash
python3 scripts/verify_container_sandbox.py --runtime
```

Pokud checker běží v jiném procesu než Chromium, musí být explicitně zadán
kladný PID cílového Chromium procesu:

```bash
python3 scripts/verify_container_sandbox.py --runtime --pid <chromium-pid>
```

Checker čte pouze interně sestavený `/proc/self/status` nebo
`/proc/<pid>/status`; cestu k souboru nelze dodat jako vstup. Kontrola proto
musí být provedena ve stejném bezpečnostním kontextu jako cílový Chromium
proces, případně přes jeho skutečný PID. `/proc` potvrzuje stav procesu, ale
nedokazuje identitu Docker profilu `docker-default`; ta je ověřována pouze
statickou deklarací a kontrolou artefaktů. Chybějící, duplicitní, poškozený
nebo nečitelný údaj je chyba (fail-closed).
