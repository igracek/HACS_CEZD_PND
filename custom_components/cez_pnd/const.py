"""Constants for the CEZ Distribuce PND integration."""
from typing import Final

DOMAIN: Final = "cez_pnd"
PLATFORMS: Final = ["sensor", "binary_sensor"]

# Configuration keys (Config Flow & Storage)
CONF_USERNAME: Final = "username"
CONF_PASSWORD: Final = "password"
CONF_EAN: Final = "ean"
CONF_ELM: Final = "elm"
CONF_TARIFF_ENTITY: Final = "tariff_entity"
CONF_SCAN_TIME: Final = "scan_time"
CONF_BROWSER_HEADLESS: Final = "browser_headless"
CONF_DEBUG_MODE: Final = "debug_mode"
CONF_DEBUG_DIR: Final = "debug_dir"

# Default values
DEFAULT_SCAN_TIME: Final = "06:00"
DEFAULT_BROWSER_HEADLESS: Final = True
DEFAULT_DEBUG_MODE: Final = False
DEFAULT_DEBUG_DIR: Final = "/config/cez_pnd_debug"

# URLs & Navigation Origin States (SEC07-03 & SEC08-02)
URL_PND_LOGIN: Final = "https://pnd.cezdistribuce.cz/cezpnd2/external/dashboard/view"

# Navigation Origin States (SEC07-03 & SEC08-02)
ORIGIN_STATE_PREAUTH: Final = "preauth"
ORIGIN_STATE_AUTH: Final = "auth"  # Backward-compatible alias / Pre-auth landing
ORIGIN_STATE_CREDENTIALS: Final = "credentials"
ORIGIN_STATE_IDP: Final = "idp"  # Alias pro credential entry fázi
ORIGIN_STATE_APP: Final = "app"

# Granular Allowed Hostnames and Origins by State
PREAUTH_ALLOWED_HOSTNAMES: Final = (
    "pnd.cezdistribuce.cz",
    "mepas.cez.cz",
    "dip.cezdistribuce.cz",
)
PREAUTH_ALLOWED_ORIGINS: Final = (
    "https://pnd.cezdistribuce.cz",
    "https://mepas.cez.cz",
    "https://dip.cezdistribuce.cz",
)

# Credential entry is STRICTLY restricted to legitimate identity provider hosts (excludes pnd.cezdistribuce.cz)
IDP_ALLOWED_HOSTNAMES: Final = (
    "mepas.cez.cz",
    "dip.cezdistribuce.cz",
)
IDP_ALLOWED_ORIGINS: Final = (
    "https://mepas.cez.cz",
    "https://dip.cezdistribuce.cz",
)

APP_ALLOWED_HOSTNAMES: Final = (
    "pnd.cezdistribuce.cz",
)
APP_ALLOWED_ORIGINS: Final = (
    "https://pnd.cezdistribuce.cz",
)
APP_PATH_PREFIX: Final = "/cezpnd2"

# SEC10-07: Host/path contracts for authentication and credential entry phases (CWE-346)
CREDENTIAL_ENTRY_ALLOWED_PATH_PREFIXES: Final = (
    "/cas",
    "/idp",
    "/login",
    "/cezpnd2",
)

AUTH_HOST_PATH_CONTRACTS: Final = {
    "mepas.cez.cz": ("/cas", "/idp", "/login"),
    "dip.cezdistribuce.cz": ("/login", "/cezpnd2", "/idp"),
    "pnd.cezdistribuce.cz": ("/cezpnd2",),
}

# Mappings by State
ALLOWED_HOSTNAMES_BY_STATE: Final = {
    ORIGIN_STATE_PREAUTH: PREAUTH_ALLOWED_HOSTNAMES,
    ORIGIN_STATE_AUTH: PREAUTH_ALLOWED_HOSTNAMES,
    ORIGIN_STATE_CREDENTIALS: IDP_ALLOWED_HOSTNAMES,
    ORIGIN_STATE_IDP: IDP_ALLOWED_HOSTNAMES,
    ORIGIN_STATE_APP: APP_ALLOWED_HOSTNAMES,
}
ALLOWED_ORIGINS_BY_STATE: Final = {
    ORIGIN_STATE_PREAUTH: PREAUTH_ALLOWED_ORIGINS,
    ORIGIN_STATE_AUTH: PREAUTH_ALLOWED_ORIGINS,
    ORIGIN_STATE_CREDENTIALS: IDP_ALLOWED_ORIGINS,
    ORIGIN_STATE_IDP: IDP_ALLOWED_ORIGINS,
    ORIGIN_STATE_APP: APP_ALLOWED_ORIGINS,
}

AUTH_ALLOWED_HOSTNAMES: Final = PREAUTH_ALLOWED_HOSTNAMES
AUTH_ALLOWED_ORIGINS: Final = PREAUTH_ALLOWED_ORIGINS

# Backward-compatibility aliases
ALLOWED_ORIGIN: Final = "https://pnd.cezdistribuce.cz"
ALLOWED_ORIGINS: Final = AUTH_ALLOWED_ORIGINS
ALLOWED_HOSTNAMES: Final = AUTH_ALLOWED_HOSTNAMES

# Error Codes
ERR_AUTH: Final = "ERR_AUTH"
ERR_CAPTCHA: Final = "ERR_CAPTCHA"
ERR_LOCKED: Final = "ERR_LOCKED"
ERR_ELM_NOT_FOUND: Final = "ERR_ELM_NOT_FOUND"
ERR_MAINTENANCE: Final = "ERR_MAINTENANCE"
ERR_TIMEOUT: Final = "ERR_TIMEOUT"
ERR_SCRAPER: Final = "ERR_SCRAPER"
ERR_INSECURE_BROWSER: Final = "ERR_INSECURE_BROWSER"
ERR_PARSER: Final = "ERR_PARSER"
ERR_PORTAL: Final = "ERR_PORTAL"
ERR_UNKNOWN: Final = "ERR_UNKNOWN"

# Disallowed browser security flags (SEC10-03 / CWE-693 / CWE-250)
DISALLOWED_BROWSER_FLAGS: Final[Tuple[str, ...]] = (
    "--no-sandbox",
    "--disable-seccomp-filter-sandbox",
    "--disable-setuid-sandbox",
)

# Statistics prefixes / identifiers
STATISTIC_PREFIX: Final = "cez_pnd"
STATISTIC_CONSUMPTION: Final = "consumption"
STATISTIC_CONSUMPTION_VT: Final = "consumption_vt"
STATISTIC_CONSUMPTION_NT: Final = "consumption_nt"
STATISTIC_PRODUCTION: Final = "production"

# Services
SERVICE_FETCH_DATA: Final = "fetch_data"
ATTR_DATE_RANGE: Final = "date_range"
ATTR_EAN: Final = "ean"


def mask_ean(ean: str) -> str:
    """Mask 18-digit EAN for safe UI/logging display (8591********6789)."""
    if not ean:
        return "********"
    clean = str(ean).strip()
    if len(clean) == 18:
        return f"{clean[:4]}********{clean[-4:]}"
    elif len(clean) >= 8:
        return f"{clean[:4]}{'*' * (len(clean) - 8)}{clean[-4:]}"
    return "********"


def mask_elm(elm: str) -> str:
    """Mask ELM for safe UI/logging display (***5678)."""
    if not elm:
        return ""
    clean = str(elm).strip()
    if not clean:
        return ""
    if len(clean) > 4:
        return f"***{clean[-4:]}"
    return "***"

