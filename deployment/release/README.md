# Release dependency verification

Tyto soubory popisují ověřovací baseline pro **Home Assistant Core 2026.10.4,
CPython 3.14 a Linux**, vyřešenou dne 2026-10-26. Nejde o instalační lock,
který by měl Home Assistant použít místo svého sdíleného resolveru.

Minimální podporovaná a otestovaná verze HA je **2026.10.4** (shodně v obou
`hacs.json`). Starší vydání tímto snapshotem nejsou bezpečnostně kvalifikována.
Kořeny integrace zůstávají `selenium==4.49.0` a `beautifulsoup4==4.15.0`;
`requests`, `certifi` ani `urllib3` nepřidávejte do manifestu.
Sdílený kandidát používá `certifi==2026.10.23` a `urllib3==2.8.0`, nikoli původní
zranitelné verze `2026.7.22` a `2.7.0`. Ostatní verze closure zůstávají stejné;
online gate ověřuje skutečné `requires_dist`, včetně extra `urllib3[socks]`.
Jde o closure této integrace, nikoli bezpečnostní audit celého HA nebo browseru.

Provenance HA 2026.10.4 je připnuta na veřejný commit
[`357cae5c598dfcd7a0ea7dc5b1facccd4ec6037b`](https://github.com/home-assistant/core/tree/357cae5c598dfcd7a0ea7dc5b1facccd4ec6037b).
Gate kontroluje SHA-256 jeho `pyproject.toml` a
`homeassistant/package_constraints.txt`, verzi HA, Python `>=3.14.2` a pin
`requests==2.34.2`; PyPI metadata následně ověřují celý aktivní graf.
Diagnostika porovnává instalované verze se snapshotem pro aplikaci **1.1.9**,
ale neprovádí živý OSV dotaz a netvrdí budoucí bezpečnost.

- `requirements.in` přesně pinuje dva kořeny vlastněné integrací a
  `requests==2.34.2`, který poskytuje HA Core.
- `requirements-lock.txt` uzavírá všech 19 runtime balíčků na konkrétní
  platformně nezávislé PyPI wheel artifacty a jejich SHA-256.
- `custom_components/cez_pnd/sbom.json` je jediný kanonický CycloneDX 1.5 SBOM
  se stejným closure, dependency graphem a rolemi původu.
- `advisory-attestation.json` je historický OSV snapshot. Platí jen pro znalosti
  služby v `checked_at`; nikdy nedokazuje budoucí bezpečnost.

Před vydáním spusťte online fail-closed gate:

```bash
python3 scripts/verify_release_dependencies.py
```

Gate ověří zveřejněné PyPI URL a hashe, znovu vypočítá aktivní tranzitivní
closure pro zadanou baseline a dotáže OSV. Výpadek či neúplná odpověď je chyba.
Po vědomém přezkoumání lze nový snapshot vygenerovat pomocí
`--print-attestation`; skript jej záměrně sám nepřepisuje.

Pro lokální kontrolu driftu bez jakéhokoli tvrzení o aktuálních advisories:

```bash
python3 scripts/verify_release_dependencies.py --offline
```
