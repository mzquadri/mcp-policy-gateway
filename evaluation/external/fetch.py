"""Fetching an external corpus without taking a copy of it.

Neither MCPTox nor MCP-Guard publishes a licence, so default copyright applies and no
redistribution right is granted. This repository therefore vendors none of their data. What
is committed here is the pin - a URL, a commit, and a digest - and what is committed in
`runs/` is the result. The payloads live in a gitignored cache that each reader fills from
the original source, which is also the correct way for that source to be cited.

The digest is not decoration. A benchmark number published against a corpus that can change
underneath it is exactly the failure `munich-accident-forecasting` guards at 1e-9, and the
same rule applies here: if the bytes are not the bytes the number was computed from, the run
stops rather than silently re-pinning.

Network use is confined to this module. `evaluation/benchmark.py` and `make check` stay
offline, which is the property that lets the internal numbers reproduce anywhere.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CACHE = ROOT / ".cache" / "external"

TIMEOUT = 60
#: Nothing published here is close to this size; a bigger body means the pin is wrong.
MAX_BYTES = 64 * 1024 * 1024

Fetcher = Callable[[str], bytes]


class ExternalCorpusError(RuntimeError):
    """Base for every way the external corpus can fail to arrive intact."""


class HashMismatch(ExternalCorpusError):
    """The bytes are not the bytes the pin names."""


class Unreachable(ExternalCorpusError):
    """The source could not be reached."""


@dataclass(frozen=True, slots=True)
class Source:
    """One pinned external file, and the provenance that has to travel with it."""

    name: str
    url: str
    #: The commit the URL is pinned to. A branch URL would make the pin meaningless.
    ref: str
    sha256: str
    citation: str
    licence: str
    cache_root: Path = DEFAULT_CACHE

    @property
    def cached(self) -> Path:
        return self.cache_root / self.ref[:12] / f"{self.name}.json"


def _download(url: str) -> bytes:
    request = urllib.request.Request(url)
    request.add_header("User-Agent", "mcp-policy-gateway-external-validation")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            body = response.read(MAX_BYTES + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise Unreachable(f"could not fetch {url}: {exc}") from exc
    if len(body) > MAX_BYTES:
        raise ExternalCorpusError(f"{url} is larger than {MAX_BYTES} bytes; check the pin")
    return body


def _verify(source: Source, body: bytes, where: str) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    if digest != source.sha256:
        raise HashMismatch(
            f"{source.name}: {where} has digest {digest}, pin says {source.sha256}. "
            "The corpus has changed, or the pin is wrong. Re-pin deliberately and note "
            "it in the write-up; do not update it to make a run pass."
        )
    return body


def load(source: Source, *, fetcher: Fetcher | None = None) -> bytes:
    """Return the pinned bytes, fetching once and verifying every time.

    The cache is verified on read as well as on write, so a half-written or edited cache
    file fails the same way a changed upstream would.
    """
    if source.cached.exists():
        return _verify(source, source.cached.read_bytes(), "cache")

    body = (fetcher or _download)(source.url)
    _verify(source, body, "download")

    source.cached.parent.mkdir(parents=True, exist_ok=True)
    # Written via a sibling temp file so an interrupted run cannot leave a cache entry
    # that looks complete.
    tmp = source.cached.with_suffix(".part")
    tmp.write_bytes(body)
    tmp.replace(source.cached)
    return body


def digest_of(path: Path) -> str:
    """Helper for pinning a newly chosen source."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


__all__ = [
    "DEFAULT_CACHE",
    "ExternalCorpusError",
    "HashMismatch",
    "Source",
    "Unreachable",
    "digest_of",
    "load",
]
