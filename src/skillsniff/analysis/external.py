"""External resource discovery and trust classification.

Every URL, package, and repository a skill points at is something the skill
trusts and the reviewer probably has not read. This module finds them and sorts
them by *mutability*, because mutability is what determines whether reviewing
the skill once tells you anything about what it will do tomorrow.

Nothing here performs network access. Classification is entirely structural:
a GitHub URL carrying a 40-hex commit SHA is pinned, the same URL on ``main``
is not, and that distinction is decidable offline. Live resolution is a
separate, opt-in concern (see ``docs/LIMITATIONS.md``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

from skillsniff.model.finding import Evidence


class TrustLevel(str, Enum):
    """How much a reference can change after review."""

    PINNED = "pinned"          # immutable: commit SHA, digest, exact version
    VERSIONED = "versioned"    # a version, but a range or tag that can move
    MUTABLE = "mutable"        # branch, "latest", bare URL
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"  # paste sites, shorteners, raw IPs, odd TLDs

    @property
    def label(self) -> str:
        return {
            TrustLevel.PINNED: "pinned (immutable)",
            TrustLevel.VERSIONED: "versioned (tag may move)",
            TrustLevel.MUTABLE: "mutable (content can change after review)",
            TrustLevel.UNKNOWN: "unknown",
            TrustLevel.SUSPICIOUS: "suspicious",
        }[self]


class ResourceKind(str, Enum):
    URL = "url"
    GIT_REPO = "git-repository"
    RAW_FILE = "raw-file"
    PACKAGE = "package"
    REGISTRY = "registry"
    DOCUMENTATION = "documentation"
    REMOTE_SCRIPT = "remote-script"


#: Hosts whose whole purpose is serving mutable, anonymous content. A skill
#: fetching from one of these cannot be meaningfully reviewed.
PASTE_HOSTS = frozenset(
    {
        "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "dpaste.com",
        "termbin.com", "transfer.sh", "0x0.st", "file.io", "anonfiles.com",
        "gofile.io", "temp.sh", "bashupload.com", "oshi.at", "envs.sh",
        # paste.c-net.org is the destination in Snyk's published ToxicSkills
        # demo skill. It was absent, so the documented sample's exfiltration
        # endpoint was classified as an ordinary host.
        "paste.c-net.org", "controlc.com", "rentry.co", "dpaste.org",
        "ix.io", "sprunge.us", "clbin.com", "0bin.net", "privatebin.net",
    }
)

#: Leftmost labels that identify a paste service structurally. A curated list
#: cannot keep up with this class — the services are numerous, short-lived, and
#: trivially replaced — so the host's own name carries part of the signal.
_PASTE_LABELS = frozenset({"paste", "pastebin", "hastebin", "ghostbin", "dpaste", "termbin"})


def is_paste_host(host: str) -> bool:
    """True for a known or structurally-identifiable paste or file-drop host."""
    return host in PASTE_HOSTS or host.split(".")[0] in _PASTE_LABELS

URL_SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "s.id", "tiny.cc",
    }
)

#: Hosts that serve raw file content rather than a rendered page.
RAW_HOSTS = frozenset(
    {
        "raw.githubusercontent.com", "gist.githubusercontent.com",
        "gitlab.com", "bitbucket.org", "codeload.github.com",
        "objects.githubusercontent.com",
    }
)

REGISTRY_HOSTS = {
    "pypi.org": "pypi",
    "files.pythonhosted.org": "pypi",
    "registry.npmjs.org": "npm",
    "www.npmjs.com": "npm",
    "npmjs.com": "npm",
    "rubygems.org": "rubygems",
    "crates.io": "cargo",
    "proxy.golang.org": "go",
    "hub.docker.com": "docker",
    "ghcr.io": "oci",
}

SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".ps1", ".py", ".rb", ".pl", ".js", ".exe", ".bin")

_URL_RE = re.compile(
    r"""(?xi)
    \b(?:https?|ftp|git\+https?|ssh)://
    [^\s<>"'`\)\]\}\\]+
    """
)
_IP_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b")
_MUTABLE_REF_RE = re.compile(r"/(?:blob|raw|archive|tree)/(main|master|HEAD|develop|latest)\b", re.IGNORECASE)

#: TLDs disproportionately represented in throwaway infrastructure. Presence is
#: a weak signal on its own and is only ever combined with other evidence.
LOW_REPUTATION_TLDS = frozenset({".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click", ".zip", ".mov"})


PRIVATE_HOST_RE = re.compile(
    r"^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|"
    r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"[\w.-]+\.local|host\.docker\.internal)$",
    re.IGNORECASE,
)

EXAMPLE_HOST_RE = re.compile(
    r"^(?:[\w.-]+\.)?(?:example\.(?:com|org|net)|test|invalid|localhost|"
    r"example|placeholder\.[\w.]+|your-[\w.-]+|<[^>]+>)$",
    re.IGNORECASE,
)



@dataclass
class ExternalResource:
    """One external thing the skill depends on."""

    raw: str
    kind: ResourceKind
    trust: TrustLevel
    host: str = ""
    scheme: str = ""
    ecosystem: str = ""
    name: str = ""
    version: str = ""
    pinned_to: str = ""
    reasons: list[str] = field(default_factory=list)
    evidence: Evidence | None = None

    @property
    def is_mutable(self) -> bool:
        return self.trust in (TrustLevel.MUTABLE, TrustLevel.UNKNOWN, TrustLevel.SUSPICIOUS)

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "raw": self.raw,
            "kind": self.kind.value,
            "trust": self.trust.value,
            "host": self.host,
            "reasons": list(self.reasons),
        }
        for key in ("ecosystem", "name", "version", "pinned_to", "scheme"):
            value = getattr(self, key)
            if value:
                payload[key] = value
        if self.evidence:
            payload["evidence"] = self.evidence.as_dict()
        return payload


def _strip_trailing_punctuation(url: str) -> str:
    """Markdown and prose routinely glue punctuation onto a URL."""
    while url and url[-1] in ".,;:!?'\"":
        url = url[:-1]
    # Balance parentheses so `(see https://x/a_(b))` keeps the inner pair.
    while url.endswith(")") and url.count("(") < url.count(")"):
        url = url[:-1]
    return url


def classify_url(url: str, evidence: Evidence | None = None) -> ExternalResource:
    """Classify a single URL structurally."""
    url = _strip_trailing_punctuation(url.strip())
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    reasons: list[str] = []

    kind = ResourceKind.URL
    trust = TrustLevel.MUTABLE
    ecosystem = ""
    pinned_to = ""

    if is_paste_host(host):
        kind, trust = ResourceKind.RAW_FILE, TrustLevel.SUSPICIOUS
        reasons.append("anonymous paste or file-drop host; content can change or disappear")
    elif host in URL_SHORTENERS:
        kind, trust = ResourceKind.URL, TrustLevel.SUSPICIOUS
        reasons.append("URL shortener conceals the real destination")
    elif _IP_HOST_RE.match(host):
        # A private or loopback address is ordinary development documentation,
        # not an exfiltration destination. Marking it suspicious made every
        # skill that mentions 127.0.0.1 look like a data-theft risk.
        if PRIVATE_HOST_RE.match(host):
            trust = TrustLevel.PINNED
            reasons.append("loopback or private-range address; not an external destination")
        else:
            trust = TrustLevel.SUSPICIOUS
            reasons.append("raw IP address bypasses DNS-based reputation")
    elif host in REGISTRY_HOSTS:
        kind, ecosystem = ResourceKind.REGISTRY, REGISTRY_HOSTS[host]
        trust = TrustLevel.VERSIONED
    elif host in RAW_HOSTS or host.endswith("githubusercontent.com"):
        kind = ResourceKind.RAW_FILE
    elif host in ("github.com", "gitlab.com", "bitbucket.org"):
        kind = ResourceKind.GIT_REPO

    if EXAMPLE_HOST_RE.match(host):
        trust = TrustLevel.PINNED
        reasons.append("reserved documentation domain; cannot be a real destination")

    if any(host.endswith(tld) for tld in LOW_REPUTATION_TLDS) and not EXAMPLE_HOST_RE.match(host):
        reasons.append(f"host uses a low-reputation TLD ({host.rsplit('.', 1)[-1]})")
        if trust is TrustLevel.MUTABLE:
            trust = TrustLevel.SUSPICIOUS

    sha = _SHA_RE.search(path)
    if sha:
        trust = TrustLevel.PINNED
        pinned_to = sha.group(0)
        reasons.append("pinned to an immutable commit or content hash")
    elif _MUTABLE_REF_RE.search(path):
        trust = TrustLevel.MUTABLE
        ref = _MUTABLE_REF_RE.search(path)
        assert ref is not None
        reasons.append(f"references the moving ref {ref.group(1)!r}; content can change after review")
    elif re.search(r"/(?:releases/download|archive)/v?\d+\.\d+", path):
        trust = TrustLevel.VERSIONED
        reasons.append("references a release tag; tags can be moved by the publisher")

    if path.lower().endswith(SCRIPT_SUFFIXES):
        kind = ResourceKind.REMOTE_SCRIPT
        reasons.append("points at an executable script")

    if parsed.scheme == "http":
        # Plaintext to a loopback or documentation host is not a transit risk,
        # so it must not pull the trust level back down to mutable.
        if not (PRIVATE_HOST_RE.match(host) or EXAMPLE_HOST_RE.match(host)):
            reasons.append("plaintext HTTP: content can be modified in transit")
            if trust is not TrustLevel.SUSPICIOUS:
                trust = TrustLevel.MUTABLE

    if not reasons:
        reasons.append("no pinning information found")

    return ExternalResource(
        raw=url,
        kind=kind,
        trust=trust,
        host=host,
        scheme=parsed.scheme,
        ecosystem=ecosystem,
        pinned_to=pinned_to,
        reasons=reasons,
        evidence=evidence,
    )


def find_urls(text: str, path: str) -> list[ExternalResource]:
    """Find and classify every URL in ``text``."""
    seen: set[str] = set()
    out: list[ExternalResource] = []
    for match in _URL_RE.finditer(text):
        url = _strip_trailing_punctuation(match.group(0))
        if url in seen:
            continue
        seen.add(url)
        line = text.count("\n", 0, match.start()) + 1
        out.append(classify_url(url, Evidence(path=path, line=line, excerpt=url[:160])))
    return out


def is_benign_host(host: str) -> bool:
    """True for hosts that cannot be a real exfiltration destination.

    Documentation is full of ``https://api.example.com`` and ``localhost:8000``.
    Treating those as network egress produces exactly the noise that makes a
    security tool get switched off.
    """
    if not host:
        return False
    return bool(PRIVATE_HOST_RE.match(host) or EXAMPLE_HOST_RE.match(host))
