# Release dependency verification

Tyto soubory popisují ověřovací baseline pro **Home Assistant Core 2026.8.3,
CPython 3.14 a Linux**, vyřešenou dne 2026-09-15. Nejde o instalační lock,
který by měl Home Assistant použít místo svého sdíleného resolveru.

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
