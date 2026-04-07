from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass
from typing import Final, cast
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

RIPESTAT_ANNOUNCED_PREFIXES_URL: Final[str] = (
    "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
)
RIPESTAT_MAX_ATTEMPTS: Final[int] = 3
RIPESTAT_RETRY_DELAY_SECONDS: Final[tuple[float, ...]] = (0.5, 1.0)


@dataclass(frozen=True)
class ASNLookupError(Exception):
    asn: str
    message: str

    def __str__(self) -> str:
        return f"AS{self.asn}: {self.message}"


class ASNPrefixResolver:
    def __init__(self, *, source: str, timeout_seconds: int) -> None:
        if source != "ripe":
            raise ValueError(f"unsupported ASN source: {source}")
        self._timeout_seconds = timeout_seconds
        self._cache: dict[str, list[str]] = {}

    def resolve(self, asn: str) -> list[str]:
        cached = self._cache.get(asn)
        if cached is not None:
            return cached

        prefixes = _fetch_ripe_prefixes(asn=asn, timeout_seconds=self._timeout_seconds)
        self._cache[asn] = prefixes
        return prefixes


def _fetch_ripe_prefixes(*, asn: str, timeout_seconds: int) -> list[str]:
    request_url = RIPESTAT_ANNOUNCED_PREFIXES_URL.format(asn=asn)
    last_error: ASNLookupError | None = None
    for attempt in range(RIPESTAT_MAX_ATTEMPTS):
        try:
            with urlopen(request_url, timeout=timeout_seconds) as response:
                payload = json.load(response)
            return _extract_prefixes(payload=payload, asn=asn)
        except HTTPError as exc:
            last_error = ASNLookupError(asn=asn, message=f"HTTP {exc.code}")
        except URLError as exc:
            last_error = ASNLookupError(asn=asn, message=str(exc.reason))
        except TimeoutError:
            last_error = ASNLookupError(asn=asn, message="request timed out")
        except json.JSONDecodeError:
            last_error = ASNLookupError(asn=asn, message="invalid JSON response")

        if attempt < len(RIPESTAT_RETRY_DELAY_SECONDS):
            time.sleep(RIPESTAT_RETRY_DELAY_SECONDS[attempt])

    if last_error is None:
        raise ASNLookupError(asn=asn, message="unknown ASN lookup failure")
    raise last_error


def _extract_prefixes(*, payload: object, asn: str) -> list[str]:
    if not isinstance(payload, dict):
        raise ASNLookupError(asn=asn, message="missing data object in response")

    typed_payload = cast(dict[str, object], payload)
    data = typed_payload.get("data")
    if not isinstance(data, dict):
        raise ASNLookupError(asn=asn, message="missing data object in response")

    typed_data = cast(dict[str, object], data)
    prefixes = typed_data.get("prefixes")
    if not isinstance(prefixes, list):
        raise ASNLookupError(asn=asn, message="missing prefixes in response")

    normalized_prefixes: set[str] = set()
    for item in prefixes:
        if not isinstance(item, dict):
            continue
        typed_item = cast(dict[str, object], item)
        prefix = typed_item.get("prefix")
        if not isinstance(prefix, str):
            continue
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        normalized_prefixes.add(str(network))

    if not normalized_prefixes:
        raise ASNLookupError(asn=asn, message="no prefixes returned")

    return sorted(normalized_prefixes)
