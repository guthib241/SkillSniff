"""Credential access and exfiltration rules (CRE, EXF families).

The strongest rule here is EXF001, which does not pattern-match at all: it
reports a dataflow observed in the AST from an environment or credential read to
a network sink. That is a claim about what the code *does*, not about what it
looks like, and it is correspondingly hard to evade by renaming or reformatting.

The pattern-based rules that remain are tuned against the dominant false
positive in this space — documentation. A skill that explains how to configure
``~/.aws/credentials`` is not accessing them, so mere mention at LOW confidence
is separated from an actual read at HIGH.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillsniff.analysis.context import AnalysisContext
from skillsniff.analysis.external import is_benign_host
from skillsniff.analysis.pyast import credential_kind, is_secret_name
from skillsniff.model.finding import Confidence, Evidence, Finding, Severity
from skillsniff.rules import _scan
from skillsniff.rules.base import Family, RuleMeta, emit, registry

CWE_200 = "https://cwe.mitre.org/data/definitions/200.html"
TOXICSKILLS = "https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/"

CREDENTIAL_PATH = re.compile(
    r"(?:~|\$HOME|\$\{HOME\}|/home/[\w.-]+|/Users/[\w.-]+|%USERPROFILE%)"
    r"/\.(?:ssh|aws|gnupg|kube|docker|azure|config/gh|config/gcloud)\b"
    r"|(?<![\w/])\.aws/credentials\b"
    r"|(?<![\w/])\.ssh/(?:id_[a-z0-9]+|config|known_hosts|authorized_keys)\b"
    r"|(?<![\w.])id_(?:rsa|ed25519|ecdsa|dsa)(?![\w.])"
    r"|(?<![\w/])\.(?:netrc|npmrc|pypirc|gitconfig|docker/config\.json)\b"
    r"|/etc/(?:shadow|passwd|sudoers)\b"
    r"|(?:service[_-]account|client[_-]secret)\.json\b"
    r"|Library/Keychains\b|login\.keychain\b"
    r"|AppData[\\/]Roaming[\\/].{0,30}(?:Login Data|Cookies)",
    re.IGNORECASE,
)

#: An explicit read of a credential path — the verb is what raises confidence.
#: Escapes that occur in regular expressions and never in a shell command line.
_REGEX_ESCAPE = re.compile(r"\\[sdwSDWb]|\(\?[:=!<]")

CREDENTIAL_READ = re.compile(
    r"\b(?:cat|less|more|head|tail|strings|cp|scp|rsync|tar|zip|base64|xxd|"
    r"open|read|read_text|read_bytes|readFile|readFileSync|load|slurp|Get-Content)\b"
    r"[^\n]{0,60}"
    # "credentials" and "keychain" as paths, not words: "Load KUPID
    # credentials" in a docstring is not a read of a credential store.
    r"(?:\.ssh/|\.aws/|id_rsa|id_ed25519|\.netrc|\.npmrc|\.pypirc|"
    r"(?:\.aws/|/)credentials\b|\.gnupg|Keychains?/|\.keychain(?:-db)?\b|/etc/shadow)",
    re.IGNORECASE,
)

HARDCODED_SECRET = re.compile(
    r"\bsk-[A-Za-z0-9]{32,}"
    r"|\bsk-ant-[A-Za-z0-9_-]{20,}"
    r"|\bgh[pousr]_[A-Za-z0-9]{36}"
    r"|\bgithub_pat_[A-Za-z0-9_]{50,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bASIA[0-9A-Z]{16}\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
    r"|-----BEGIN\s+(?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
    r"|\bAIza[0-9A-Za-z_-]{35}\b"
    r"|\bya29\.[0-9A-Za-z_-]{20,}"
    r"|\bglpat-[0-9A-Za-z_-]{20,}"
    r"|\bnpm_[A-Za-z0-9]{36}\b"
    r"|\bdop_v1_[a-f0-9]{64}\b"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
)

#: Obvious placeholders. A tool that flags these is a tool people stop running.
PLACEHOLDER = re.compile(
    r"(?i)(?:your|my|the|example|sample|dummy|fake|test|placeholder|xxx+|<[^>]+>|"
    r"insert|replace|redacted|abc123|1234567890|changeme|foo|bar)"
    r"|(?:X{8,}|x{8,}|0{8,}|1{8,}|A{8,}|a{8,}|\*{6,}|\.{6,})",
)

SECRET_ENV_NAME = re.compile(
    r"\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|APIKEY|"
    r"CREDENTIAL|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|AUTH|SESSION[_-]?KEY)[A-Z0-9_]*\b"
)

ENV_DUMP = re.compile(
    r"\bprintenv\b(?!\s+\w)"
    # ``env`` must be in command position. Anchoring on end-of-line alone made
    # every prose line that happens to end in the word "env" a wholesale
    # environment dump — "reads ANTHROPIC_WEBHOOK_SIGNING_KEY from env" was
    # reported at HIGH. A real dump is `env` piped, redirected, or run alone.
    r"|(?:^|[;&|]\s*)[ \t]*env\b[ \t]*(?:\||>|$)"
    r"|\bos\.environ\b(?!\s*(?:\.get\s*\(\s*[\"']|\[))"
    r"|\bprocess\.env\b(?!\s*\.)"
    r"|\bGet-ChildItem\s+Env:",
    re.MULTILINE,
)

registry.define_all(
    [
        RuleMeta(
            id="CRE001",
            title="Credential store accessed",
            family=Family.CRE,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "The skill reads a credential store — SSH private keys, AWS credentials, "
                "kubeconfig, .netrc, .npmrc, a browser credential database, or the system "
                "keychain. Confidence is HIGH when a read verb accompanies the path and LOWER "
                "when the path is merely mentioned."
            ),
            impact=(
                "These files are the keys to everything the user can reach. Reading them is the "
                "first stage of the dominant exfiltration pattern in confirmed-malicious skills."
            ),
            remediation=(
                "Do not read credential stores. Where a credential is genuinely needed, take it "
                "from an environment variable the user has deliberately set for this purpose, "
                "and document which one."
            ),
            limitations=(
                "Documentation that explains how to configure these files will match at reduced "
                "confidence. Check the cited line."
            ),
            references=(TOXICSKILLS, CWE_200),
            taxonomy=("CWE-522",),
        ),
        RuleMeta(
            id="CRE002",
            title="Hardcoded credential",
            family=Family.CRE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            explanation=(
                "A string matching the format of a live credential — an API key, personal "
                "access token, AWS key id, or PEM private key block — is committed in the skill. "
                "Recognised placeholder shapes are excluded."
            ),
            impact=(
                "The credential is exposed to everyone with access to the skill, which for a "
                "published skill is everyone. Rotation is the only remedy; deletion from the "
                "repository is not sufficient because history retains it."
            ),
            remediation=(
                "Revoke and rotate the credential now, then remove it from the file and from "
                "version-control history. Read it from the environment at runtime instead."
            ),
            limitations=(
                "Detects known credential formats only. A high-entropy string in an unrecognised "
                "format is not reported, and a realistic-looking example value may be."
            ),
            references=("https://cwe.mitre.org/data/definitions/798.html",),
            taxonomy=("CWE-798",),
        ),
        RuleMeta(
            id="CRE003",
            title="Environment dumped wholesale",
            family=Family.CRE,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The entire process environment is read or printed, rather than a specific named "
                "variable."
            ),
            impact=(
                "The environment is where agents hold API keys. Reading all of it collects every "
                "secret the process can see, including ones unrelated to the skill's purpose."
            ),
            remediation="Read only the specific variables the skill needs, by name.",
            limitations="Debug tooling and CI helper scripts do this legitimately.",
            references=(CWE_200,),
        ),
        RuleMeta(
            id="EXF001",
            title="Secret value flows to a network sink",
            family=Family.EXF,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "Dataflow analysis found a secret reaching an outbound network call: a value "
                "from an environment variable whose name marks it as a secret (TOKEN, SECRET, "
                "API_KEY, PASSWORD…), the whole environment, a credential file, or a keyring "
                "lookup. Python is read from the AST and the flow followed through assignments, "
                "f-strings, containers and concatenation; JavaScript and TypeScript from the "
                "token stream, through assignments, destructuring, template literals, object "
                "literals and containers, into fetch, axios, http(s), sockets, mail transports, "
                "DNS lookups, or a shelled-out curl."
            ),
            impact=(
                "This is exfiltration: a credential the agent holds is transmitted to a remote "
                "party. It is the single highest-severity finding this tool produces because the "
                "evidence is behavioural rather than lexical."
            ),
            remediation=(
                "Remove the transmission. If a credential must reach a service, it should be "
                "sent only to that service's documented endpoint over TLS, and the skill should "
                "state plainly which credential goes where."
            ),
            limitations=(
                "Intraprocedural, per file, and limited to Python and JavaScript/TypeScript. A "
                "flow that crosses a function boundary or a file, passes through a class "
                "attribute other than this.x, or is written in another language is not tracked "
                "here — the pattern-based EXF002 provides weaker coverage for those. A secret "
                "stored under a neutral variable name is not recognised as one. A credential "
                "sent as an authentication header to a fixed host is reported at LOW, whatever "
                "the host: the rule cannot tell a service's own endpoint from a look-alike."
            ),
            references=(TOXICSKILLS, CWE_200),
            taxonomy=("CWE-201",),
        ),
        RuleMeta(
            id="EXF002",
            title="Secret-shaped value sent to a remote endpoint",
            family=Family.EXF,
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            explanation=(
                "A network command carries a secret-shaped variable or an environment reference "
                "in its payload — for example 'curl -d \"$API_TOKEN\" https://…'. Requests to "
                "localhost, private ranges, and documentation domains are excluded."
            ),
            impact="Credentials leave the machine, to a destination the user has not agreed to.",
            remediation="Remove the credential from the request, or send it only to its own service.",
            limitations=(
                "Lexical, so it cannot confirm the variable actually holds a secret. Confidence "
                "is MEDIUM for that reason; EXF001 is the higher-assurance version."
            ),
            references=(TOXICSKILLS,),
            taxonomy=("CWE-201",),
        ),
        RuleMeta(
            id="EXF003",
            title="Data sent to an anonymous or unattributable endpoint",
            family=Family.EXF,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "An upload targets a paste site, anonymous file-drop host, URL shortener, raw IP "
                "address, or webhook-relay service."
            ),
            limitations=(
                "Uses a curated list of paste sites, shorteners, and file-drop hosts, plus "
                "raw IPs and low-reputation TLDs. A newly-registered ordinary domain looks "
                "unremarkable to this rule."
            ),
            impact=(
                "These destinations exist to receive data without attribution. There is no "
                "legitimate reason for a skill to send a user's data to one."
            ),
            remediation="Send data only to a named service the user has agreed to, over TLS.",
            references=(TOXICSKILLS,),
        ),
        RuleMeta(
            id="EXF004",
            title="Local file contents posted to a remote host",
            family=Family.EXF,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "A network command uploads file contents — 'curl --data @file', "
                "'-F file=@…', or a read piped into a sender."
            ),
            impact="Repository or filesystem contents leave the machine.",
            remediation=(
                "State exactly which file is uploaded and to where, and require confirmation "
                "before sending."
            ),
            limitations="Legitimate upload workflows match. Judge by the destination.",
        ),
        RuleMeta(
            id="EXF005",
            title="System reconnaissance output sent to a remote host",
            family=Family.EXF,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "A network command's payload contains command substitution running a "
                "host-profiling command — 'uname', 'whoami', 'hostname', 'id' — so the output "
                "of that command is what gets sent."
            ),
            impact=(
                "The operator learns which machine the agent runs on: kernel, architecture, "
                "hostname, user. That is the target-selection step of an intrusion, and it is "
                "the shape used by the skill in Snyk's published ToxicSkills demo, which "
                "posted 'uname -a' to a paste site under the guise of an allow-list check."
            ),
            remediation=(
                "Remove the call. If diagnostics genuinely need to be reported, show the user "
                "exactly what will be sent and get confirmation first."
            ),
            limitations=(
                "Lexical, and legitimate crash reporters and installers do profile the host. "
                "The finding is the shape, not proof of intent; judge it by the destination "
                "and by whether the skill's description admits to it."
            ),
            references=(TOXICSKILLS,),
            taxonomy=("CWE-200",),
        ),
        RuleMeta(
            id="EXF006",
            title="Data exfiltrated through a DNS lookup",
            family=Family.EXF,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "A DNS lookup ('nslookup', 'dig', 'host', 'drill') whose queried name is built "
                "from data — a variable, a command substitution, or a label named like a "
                "secret — so the lookup itself carries the data to whoever runs the domain's "
                "nameserver. CRITICAL when the data is shown to be a secret (a secret-named "
                "variable, a credential file, the environment) and the domain is real; HIGH "
                "when only the shape is."
            ),
            impact=(
                "DNS leaves almost every network, including ones that block HTTP egress, and "
                "a lookup does not look like data leaving. Every query delivers its name to "
                "the attacker's nameserver."
            ),
            remediation="Remove the lookup, or query a fixed name that carries no data.",
            limitations=(
                "Reserved documentation domains (example.com, .example, .test) are excluded "
                "as they are by every exfiltration rule, so a sample written against one is "
                "not reported. A lookup issued from code rather than a command is not seen."
            ),
            references=(
                "https://attack.mitre.org/techniques/T1048/003/",
            ),
            taxonomy=("CWE-200", "ATT&CK:T1048.003"),
        ),
        RuleMeta(
            id="EXF007",
            title="Secrets sent by email",
            family=Family.EXF,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "Mail is sent — an 'smtp://' address, sendmail/mail/mutt/swaks/msmtp, or "
                "Python's smtplib — on a line that also names a credential, secret, token, "
                "password, key file, or '.env'. CRITICAL when both halves are shown on the "
                "line: a concrete secret (a secret-named variable or a credential file) and an "
                "outside recipient or SMTP host; HIGH when only the secret is named."
            ),
            impact=(
                "Credentials leave over a channel most egress monitoring treats as ordinary "
                "notification traffic."
            ),
            remediation="Do not mail secrets. Send a notification that carries no credential.",
            limitations=(
                "Requires the mail command and the secret on the same line. Documentation "
                "domains are excluded. Mail assembled across several lines, or a secret held "
                "in a variable with a neutral name, is not connected."
            ),
            taxonomy=("CWE-200",),
        ),
    ]
)


def _plausible_secret(value: str) -> bool:
    """Filter placeholders out of credential-format matches."""
    if PLACEHOLDER.search(value):
        return False
    # AWS publishes AKIAIOSFODNN7EXAMPLE as the canonical example key.
    return "EXAMPLE" not in value.upper()


@registry.implement("CRE001")
def check_credential_access(context: AnalysisContext) -> Iterator[Finding]:
    reported: set[tuple[str, int | None]] = set()

    # High confidence: a read verb next to a credential path.
    for match in _scan.scan(context, CREDENTIAL_READ, limit_per_file=6):
        if _REGEX_ESCAPE.search(match.text):
            continue  # a regular expression that mentions the path, not a read of it
        reported.add((match.path, match.line))
        yield _scan.emit_match(
            "CRE001", context.name, match, confidence=Confidence.HIGH
        )

    # Structural: the AST, or the JavaScript token stream, saw a credential path
    # literal in the source (in JavaScript, only one passed to a file read).
    for file in context.files:
        analysis = file.python or file.js
        if analysis is None:
            continue
        for value, line in analysis.credential_paths:
            if (file.path, line) in reported:
                continue
            reported.add((file.path, line))
            if credential_kind(value) == "project":
                # The skill's own .env or OAuth client file: where its own key
                # lives, not a store that belongs to the user.
                yield emit(
                    "CRE001",
                    context.name,
                    message=f"{file.path}: reads a project secret file {value!r}",
                    evidence=[file.evidence(line=line, excerpt=value[:120])],
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                )
                continue
            yield emit(
                "CRE001",
                context.name,
                message=f"{file.path}: source references credential path {value!r}",
                evidence=[file.evidence(line=line, excerpt=value[:120])],
                confidence=Confidence.HIGH,
            )

    # Lower confidence: the path is mentioned without an evident read.
    for match in _scan.scan(context, CREDENTIAL_PATH, limit_per_file=4):
        if (match.path, match.line) in reported:
            continue
        reported.add((match.path, match.line))
        yield _scan.emit_match(
            "CRE001",
            context.name,
            match,
            message=f"{match.path}: references credential path {match.excerpt!r}",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            note="path referenced; no explicit read verb nearby",
        )


@registry.implement("CRE002")
def check_hardcoded_secret(context: AnalysisContext) -> Iterator[Finding]:
    for match in _scan.scan(context, HARDCODED_SECRET, limit_per_file=10):
        if not _plausible_secret(match.text):
            continue
        redacted = match.text[:10] + "…" + f"[{len(match.text)} chars]"
        yield emit(
            "CRE002",
            context.name,
            message=f"{match.path}: credential-formatted string {redacted}",
            evidence=[
                Evidence(
                    path=match.path,
                    line=match.line,
                    excerpt=redacted,
                    decode_chain=match.decode_chain,
                    note="value redacted; SkillSniff never prints a full credential",
                )
            ],
        )


@registry.implement("CRE003")
def check_env_dump(context: AnalysisContext) -> Iterator[Finding]:
    for match in _scan.scan(context, ENV_DUMP, limit_per_file=4):
        yield emit(
            "CRE003",
            context.name,
            message=f"{match.path}: reads the whole environment — {match.excerpt!r}",
            evidence=[match.evidence()],
        )


@registry.implement("EXF001")
def check_taint_flows(context: AnalysisContext) -> Iterator[Finding]:
    for file in context.files:
        analysis = file.python or file.js
        if analysis is None:
            continue
        for flow in analysis.taint_flows:
            # Sending a token in an Authorization header to a literal endpoint is
            # authentication, which is what credentials are *for*. Reporting it
            # as exfiltration is the highest-cost false positive this tool can
            # make, because it fires on correct code in ordinary API clients.
            if flow.is_authentication:
                yield emit(
                    "EXF001",
                    context.name,
                    message=(
                        f"{file.path}: {flow.source} is sent as an authentication header to a "
                        f"fixed endpoint at line {flow.sink_line} — review that the endpoint is "
                        "the credential's own service"
                    ),
                    evidence=[
                        file.evidence(
                            line=flow.sink_line,
                            excerpt=f"{flow.sink}(… headers … {flow.variable} …)",
                            note="credential used as an auth header, not sent as payload",
                        )
                    ],
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                )
                continue
            yield emit(
                "EXF001",
                context.name,
                message=(
                    f"{file.path}: value from {flow.source} (line {flow.source_line}) reaches "
                    f"{flow.sink}() at line {flow.sink_line}"
                ),
                evidence=[
                    file.evidence(
                        line=flow.source_line,
                        excerpt=f"{flow.source} → {flow.variable}",
                        note="secret source",
                    ),
                    file.evidence(
                        line=flow.sink_line,
                        excerpt=f"{flow.sink}(… {flow.variable} …)",
                        note="network sink",
                    ),
                ],
            )


SENDER = re.compile(
    # ``http`` here means the HTTPie CLI, so it has to look like a command
    # invocation. A bare \bhttp\b matched the prose "HTTP/2 protocol error" and
    # then swallowed 200 characters of documentation, which is how this rule
    # reported a credential exfiltration in a page about HTTP headers.
    #
    # The tool must open a word and be followed by something a command takes
    # (an option, a URL, a quoted or variable argument): without the leading
    # \b, "nc" matched inside "sync", "async" and "func"; without the shape,
    # "use curl for calls … API_KEY" in a sentence was a request.
    r"\b(?:curl|wget|httpie)\b(?=[ \t]+(?:-|https?://|['\"$]|\{))[^\n]{0,200}"
    r"|\b(?:nc|ncat|socat)\b(?=[ \t]+(?:-\w|\$|[\w.-]+[ \t]+\d))[^\n]{0,200}"
    r"|\bhttp\s+(?:(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|https?://|:)[^\n]{0,200}"
    r"|(?:requests|httpx|axios|fetch)\s*\.?\s*(?:post|put|patch|request)\s*\([^\n]{0,200}",
    re.IGNORECASE,
)

_URL_IN = re.compile(r"https?://([^\s/'\"$)]+)", re.IGNORECASE)

#: Where a credential is authentication rather than payload: a request header
#: (curl -H/--header, a headers= or headers: mapping) or curl's -u user:pass.
_AUTH_SPAN = re.compile(
    r"(?:-H|--header)[ \t]*=?[ \t]*(?P<q>[\"'])[^\n]*?(?P=q)"
    r"|(?:-u|--user)[ \t]+\S+"
    r"|\bheaders?[ \t]*[=:][ \t]*\{[^{}\n]*\}",
    re.IGNORECASE,
)
_SECRET_REFERENCE = re.compile(
    r"os\.environ|process\.env|printenv|" + SECRET_ENV_NAME.pattern, SECRET_ENV_NAME.flags
)


def _only_in_auth_position(text: str) -> bool:
    """Every secret in ``text`` sits inside a header or a basic-auth argument."""
    spans = [m.span() for m in _AUTH_SPAN.finditer(text)]
    secrets = [m.span() for m in _SECRET_REFERENCE.finditer(text)]
    return bool(secrets) and all(
        any(lo <= start and end <= hi for lo, hi in spans) for start, end in secrets
    )


@registry.implement("EXF002")
def check_secret_to_network(context: AnalysisContext) -> Iterator[Finding]:
    for match in _scan.scan(context, SENDER, limit_per_file=8):
        text = match.text
        if not (SECRET_ENV_NAME.search(text) or re.search(r"os\.environ|process\.env|printenv", text)):
            continue

        host_match = _URL_IN.search(text)
        host = (host_match.group(1).split(":")[0] if host_match else "").lower()
        if host and is_benign_host(host):
            continue

        secret = SECRET_ENV_NAME.search(text)
        name = secret.group(0) if secret else "environment data"
        if _only_in_auth_position(text):
            # A token in an Authorization header is what tokens are for. Same
            # judgement as EXF001: visible, at LOW, never blocking.
            yield emit(
                "EXF002",
                context.name,
                message=(
                    f"{match.path}: {name} is sent as an authentication header"
                    + (f" to {host}" if host else "")
                    + " — review that the endpoint is the credential's own service"
                ),
                evidence=[match.evidence()],
                severity=Severity.LOW,
                confidence=Confidence.LOW,
            )
            continue
        yield emit(
            "EXF002",
            context.name,
            message=f"{match.path}: network request carries {name}" + (f" to {host}" if host else ""),
            evidence=[match.evidence()],
        )


@registry.implement("EXF003")
def check_anonymous_destination(context: AnalysisContext) -> Iterator[Finding]:
    from skillsniff.analysis.external import TrustLevel

    upload = re.compile(
        r"\b(?:curl|wget|nc|ncat|socat|http)\b|\.(?:post|put)\s*\(|\bupload\b", re.IGNORECASE
    )

    for file in context.text_files():
        view = file.view
        if view is None:
            continue
        lines = view.raw.splitlines()
        for resource in file.urls:
            if resource.trust is not TrustLevel.SUSPICIOUS:
                continue
            evidence = resource.evidence
            if evidence is None or evidence.line is None:
                continue
            window = "\n".join(lines[max(0, evidence.line - 2) : evidence.line + 1])
            if not upload.search(window):
                continue
            yield emit(
                "EXF003",
                context.name,
                message=f"{file.path}: sends data to {resource.host} — {'; '.join(resource.reasons)}",
                evidence=[
                    Evidence(
                        path=file.path,
                        line=evidence.line,
                        excerpt=resource.raw[:160],
                        note="; ".join(resource.reasons),
                    )
                ],
            )


FILE_UPLOAD = re.compile(
    r"curl\b[^\n]{0,160}(?:--data[- ]?(?:binary|urlencode)?|-d|-F|--form|-T|--upload-file)\s*[\"']?@"
    r"|(?:cat|tar|zip|base64)\b[^\n]{0,80}\|\s*(?:curl|wget|nc|ncat)\b"
    r"|files\s*=\s*\{[^\n}]{0,120}open\s*\(",
    re.IGNORECASE,
)


#: Commands whose only output is a description of the machine. Sending any of
#: these somewhere is reconnaissance regardless of what the payload is called.
RECON = re.compile(
    r"\b(?:curl|wget|httpie|nc|ncat|socat)\b[^\n]{0,200}"
    r"(?:\$\(|`)\s*(?:uname|whoami|hostname|id|w|who|arch|uptime|sw_vers|"
    r"systeminfo|lsb_release|ifconfig|ipconfig|ps|last|groups)\b",
    re.IGNORECASE,
)


@registry.implement("EXF005")
def check_recon_exfiltration(context: AnalysisContext) -> Iterator[Finding]:
    for match in _scan.scan(context, RECON, limit_per_file=5):
        host_match = _URL_IN.search(match.text)
        host = (host_match.group(1).split(":")[0] if host_match else "").lower()
        if host and is_benign_host(host):
            continue
        yield emit(
            "EXF005",
            context.name,
            message=f"{match.path}: sends host information — {match.excerpt!r}",
            evidence=[match.evidence()],
        )


@registry.implement("EXF004")
def check_file_upload(context: AnalysisContext) -> Iterator[Finding]:
    for match in _scan.scan(context, FILE_UPLOAD, limit_per_file=5):
        host_match = _URL_IN.search(match.text)
        host = (host_match.group(1).split(":")[0] if host_match else "").lower()
        if host and is_benign_host(host):
            continue
        yield emit(
            "EXF004",
            context.name,
            message=f"{match.path}: uploads file contents — {match.excerpt!r}",
            evidence=[match.evidence()],
        )


#: A DNS lookup tool, then a name whose leftmost labels carry data.
DNS_EXFIL = re.compile(
    r"\b(?:nslookup|dig|host|drill)\b[^\n|;]{0,40}?\s"
    r"(?P<name>"
    r"(?:\$\{?\w+\}?|\$\([^)\n]{1,80}\)|`[^`\n]{1,80}`)[\w.${}()`-]*\.[\w-]+(?:\.[\w-]+)+"
    r"|[\w-]*(?:token|secret|passw(?:or)?d|api[_-]?key|credential)[\w-]*\.[\w-]+(?:\.[\w-]+)+"
    r")",
    re.IGNORECASE,
)

#: Sending mail, by URL, command, or library.
MAIL_SEND = re.compile(
    r"\bsmtps?://(?P<host>[^\s/'\"<>:]+)"
    # sendmail, mutt, swaks and msmtp are unambiguous tool names. "mail" is
    # also an English word, so it counts only in command position — piped into,
    # or at the start of a command — and with a flag. Matching the bare word
    # fired on the sentence "sends a notification by mail; no secret is on the
    # line", which names a secret and the word "mail" and sends nothing.
    r"|\b(?:sendmail|mutt|swaks|msmtp)\b[^\n]{0,160}"
    r"|(?:^|[|;&]|\$\()[ \t]*mailx?[ \t]+-[A-Za-z][^\n]{0,160}"
    r"|\bsmtplib\.SMTP(?:_SSL)?\s*\(",
    re.IGNORECASE | re.MULTILINE,
)

#: Something on the same line that names a secret.
SECRET_CONTEXT = re.compile(
    r"\b(?:secrets?|credentials?|passwords?|passwd|tokens?|api[\s_-]?keys?|private[\s_-]?keys?)\b"
    r"|\.env\b|\bid_rsa\b|\.aws/credentials|\.ssh/",
    re.IGNORECASE,
)


def _line_of(match: _scan.Match) -> str:
    view = match.file.view
    if view is None or match.projection == "decoded":
        return match.text
    start = view.raw.rfind("\n", 0, match.start) + 1
    end = view.raw.find("\n", match.end)
    return view.raw[start : end if end != -1 else len(view.raw)]


#: A shell variable reference, for judging what a command carries by the name.
_VARIABLE = re.compile(r"\$\{?([A-Za-z_]\w*)")
#: A mail recipient, whose domain is the destination.
_RECIPIENT = re.compile(r"\b[\w.+-]+@((?:[\w-]+\.)+[A-Za-z]{2,})\b")
#: Command substitution that dumps the environment.
_ENV_SUBSTITUTION = re.compile(r"(?:\$\(|`)[^)`]*\b(?:env|printenv)\b")


def _carries_secret(text: str) -> str:
    """The secret ``text`` evidently carries — a secret-named variable, a credential
    file, or the environment — or "" when the data is not shown to be a secret."""
    for name in _VARIABLE.findall(text):
        if is_secret_name(name):
            return f"${name}"
    path = CREDENTIAL_PATH.search(text)
    if path:
        return path.group(0)
    if _ENV_SUBSTITUTION.search(text):
        return "the environment"
    return ""


@registry.implement("EXF006")
def check_dns_exfiltration(context: AnalysisContext) -> Iterator[Finding]:
    for match in _scan.scan(context, DNS_EXFIL, limit_per_file=4):
        name = (DNS_EXFIL.match(match.text) or DNS_EXFIL.search(match.text))
        queried = name.group("name") if name else match.text
        # The registrable part is what an attacker controls; a reserved
        # documentation domain cannot be a real destination.
        labels = [part for part in queried.split(".") if part]
        domain = ".".join(labels[-2:]).lower() if len(labels) >= 2 else queried.lower()
        if is_benign_host(domain) or is_benign_host(queried.lower()):
            continue
        # Both halves evidenced — a secret in the name, a real domain to
        # receive it — is exfiltration, not a lookup that happens to use data.
        secret = _carries_secret(queried)
        if secret:
            yield _scan.emit_match(
                "EXF006",
                context.name,
                match,
                message=f"{match.path}: a DNS lookup carries {secret} to {domain}",
                severity=Severity.CRITICAL,
            )
            continue
        yield _scan.emit_match("EXF006", context.name, match)


@registry.implement("EXF007")
def check_mail_exfiltration(context: AnalysisContext) -> Iterator[Finding]:
    for match in _scan.scan(context, MAIL_SEND, limit_per_file=4):
        line = _line_of(match)
        if not (SECRET_CONTEXT.search(line) or SECRET_ENV_NAME.search(line)):
            continue
        host = (match.text.split("://", 1)[1].split("/")[0].split(":")[0]
                if "://" in match.text else "")
        if host and is_benign_host(host.lower()):
            continue
        # A concrete secret on the line and an outside recipient: the mail is
        # shown to leave with the credential. A secret *word* near a mail
        # command, with nowhere shown to send it, stays HIGH.
        secret = _carries_secret(line)
        recipients = [d.lower() for d in _RECIPIENT.findall(line) if not is_benign_host(d.lower())]
        destination = host if host and not is_benign_host(host.lower()) else (recipients[0] if recipients else "")
        if secret and destination:
            yield _scan.emit_match(
                "EXF007",
                context.name,
                match,
                message=f"{match.path}: mails {secret} to {destination}",
                severity=Severity.CRITICAL,
            )
            continue
        yield _scan.emit_match("EXF007", context.name, match)
