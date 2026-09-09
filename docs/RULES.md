# Rule catalogue

87 rules in 16 families, generated from the registry by
`scripts/gen_rules_doc.py` for SkillSniff 0.2.0. Do not edit by hand.

`skillsniff explain <RULE>` prints any entry below, including its limitations.

Severity answers "how bad if true". Confidence answers "how sure the detection
is". They are separate so a high-severity, low-confidence finding can surface for
review without failing a build.

The `SPEC` and `QUA` families sit outside the security taxonomy and never
contribute to the security verdict.


## Index

| Family | Rules | Scope |
| --- | --- | --- |
| [`ARC`](#arc) Archive and nested artifact risk | 3 | security |
| [`CON`](#con) Capability / contract mismatch | 9 | security |
| [`CRE`](#cre) Credential and secret access | 3 | security |
| [`EVA`](#eva) Scanner evasion | 4 | security |
| [`EXE`](#exe) Execution | 6 | security |
| [`EXF`](#exf) Exfiltration | 4 | security |
| [`INJ`](#inj) Prompt / instruction injection | 6 | security |
| [`MCP`](#mcp) Tool and MCP abuse | 3 | security |
| [`MEM`](#mem) Memory and state | 2 | security |
| [`NET`](#net) Network behaviour | 3 | security |
| [`OBS`](#obs) Obfuscation | 6 | security |
| [`PER`](#per) Persistence | 2 | security |
| [`PRV`](#prv) Privilege and safety bypass | 3 | security |
| [`QUA`](#qua) Authoring quality | 18 | not security |
| [`SPEC`](#spec) Specification compliance | 10 | not security |
| [`SUP`](#sup) Supply chain | 5 | security |

## ARC

**Archive and nested artifact risk**

### `ARC001` — Archive path traversal attempt

**critical** · high confidence

**Detects.** An archive bundled with the skill contains a member whose name escapes the extraction directory via '..', an absolute path, or a drive letter. SkillSniff refuses such members and never extracts to disk.

**Why it matters.** Extracting the archive with an ordinary tool would write outside the intended directory — overwriting shell profiles, SSH keys, or agent configuration. This is Zip Slip.

**Fix.** Rebuild the archive with relative paths inside a single top-level directory, or remove it.

**Cannot detect.** Detects traversal in ZIP and TAR members. An archive format this scanner does not parse, or one whose members are encrypted, is reported as a coverage gap by ARC002 instead.

**Taxonomy.** `CWE-22`

**References.** [1](https://cwe.mitre.org/data/definitions/22.html)

### `ARC002` — Archive could not be fully inspected

**medium** · high confidence

**Detects.** An archive was encrypted, exceeded the decompression-ratio limit, nested deeper than the depth limit, or otherwise could not be read.

**Why it matters.** Content inside it was not analysed. Any 'no issues found' result excludes whatever this archive contains.

**Fix.** Ship the contents unarchived so they can be reviewed, or remove the archive.

### `ARC003` — Archive bundled with the skill

**low** · high confidence

**Detects.** The skill bundles an archive. SkillSniff inspects inside it, but archives make human review substantially less likely to happen.

**Why it matters.** Content that reviewers are unlikely to open, shipped inside the artifact.

**Fix.** Ship the files unarchived unless there is a specific reason not to.

## CON

**Capability / contract mismatch**

### `CON001` — Capability mismatch between description and behaviour

**high** · medium confidence

**Detects.** The skill exercises privileged capabilities that its description and declared tools do not account for. Capabilities are inferred separately from the description, the 'allowed-tools' list, the instruction body, bundled code, dependency manifests, and external references, then compared.

**Why it matters.** The user consented to what the description said. Every capability beyond that is reach they did not agree to, and it is the shape most commonly seen in skills that are functional on the surface and malicious underneath.

**Fix.** Either narrow the implementation to what the description promises, or update the description and 'allowed-tools' to state the full surface honestly.

**Cannot detect.** Capability inference from prose is approximate. A skill can legitimately imply a capability in wording this tool does not recognise, so review the evidence before treating a mismatch as intent.

**Taxonomy.** `LLM06:ExcessiveAgency`

### `CON002` — Undeclared privileged capability

**medium** · medium confidence

**Detects.** A privileged capability is evidenced in the skill's behaviour but appears in no claim the skill makes about itself.

**Why it matters.** A reviewer reading the frontmatter does not learn that the skill can do this. Policy engines that gate on declarations will not gate on it either.

**Fix.** Declare the capability in 'allowed-tools' or describe it in the description.

**Taxonomy.** `LLM06:ExcessiveAgency`

### `CON003` — Declared capability never used

**low** · low confidence

**Detects.** The skill declares a tool granting a privileged capability that no instruction, script, or dependency appears to use.

**Why it matters.** Unused permissions widen the blast radius for no benefit. If the skill is later compromised, the attacker inherits the grant.

**Fix.** Remove the unused entry from 'allowed-tools'.

**Cannot detect.** Static analysis cannot see every use. A capability exercised only through prose this tool does not parse will appear unused.

**Taxonomy.** `LLM06:ExcessiveAgency`

### `CON004` — Broad capability surface for a narrow stated purpose

**high** · medium confidence

**Detects.** The skill describes a narrow, local task but exercises three or more distinct privileged capability groups.

**Why it matters.** The gap between stated purpose and actual reach is the practical definition of excessive privilege.

**Fix.** Split the skill, or narrow its implementation to its stated purpose.

**Cannot detect.** 'Narrow purpose' is inferred from description length and capability breadth, both crude proxies. A terse description on a genuinely broad tool will match.

**Taxonomy.** `LLM06:ExcessiveAgency`

### `CON010` — Lethal trifecta: private data, untrusted input, and external communication

**high** · medium confidence

**Detects.** The skill combines access to private data (credentials, environment, or the filesystem), exposure to untrusted external content, and the ability to send data outward. Each leg is reported with its own evidence.

**Why it matters.** An injection delivered through the untrusted content can instruct the agent to read the private data and transmit it. No software vulnerability is required: the combination is the vulnerability.

**Fix.** Break one leg. Most often the cheapest is to remove the outbound channel, or to restrict it to a fixed allowlisted destination that cannot receive arbitrary data.

**Cannot detect.** Presence of all three legs is not proof of a vulnerability; a skill can hold all three and handle them safely. This is a prompt to review the data path, not a defect on its own.

**Taxonomy.** `LLM01:PromptInjection`, `LLM06:ExcessiveAgency`

**References.** [1](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)

### `CON011` — Credential access combined with network egress

**high** · medium confidence

**Detects.** The skill both reads credentials and makes outbound network requests. This is the two-step shape of exfiltration, reported even when no direct dataflow between them was observed.

**Why it matters.** Every precondition for credential exfiltration is present in one artifact.

**Fix.** Separate the concerns, or state plainly which credential is sent to which service and why.

**Cannot detect.** Legitimate for any skill that authenticates to an API, which is most of them. This rule reports co-occurrence, not a data path; EXF001 is the higher-confidence version, based on dataflow actually observed in the AST.

**References.** [1](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)

### `CON012` — Untrusted content combined with shell execution

**high** · medium confidence

**Detects.** The skill retrieves remote content and also executes shell commands, so attacker-influenced text and a command interpreter are present together.

**Why it matters.** Content fetched from a remote source can steer command construction, turning a content compromise into command execution.

**Fix.** Never interpolate fetched content into a command. Use argument lists and validate against an allowlist.

**Cannot detect.** Presence of both capabilities is not proof they are connected. No dataflow between the fetched content and the command is established; this is a prompt to check the path.

**References.** [1](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)

### `CON013` — Mutable dependency combined with privileged execution

**medium** · medium confidence

**Detects.** The skill depends on something that can change after review and also executes code with privilege.

**Why it matters.** A future version of the dependency inherits the skill's execution privilege without any review step.

**Fix.** Pin the dependency, or drop the privileged execution.

**References.** [1](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)

### `CON014` — Persistence combined with privileged capability

**high** · medium confidence

**Detects.** The skill writes persistent state or configuration and also holds a privileged capability such as execution, network access, or credential access.

**Why it matters.** A one-time execution becomes a standing one: the persisted state re-establishes the privileged behaviour in future sessions.

**Fix.** Remove the persistence, or narrow what is persisted to inert data.

**Cannot detect.** Legitimate for a skill that caches results and also makes network calls. Judge by what is persisted and where.

**References.** [1](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)

## CRE

**Credential and secret access**

### `CRE001` — Credential store accessed

**critical** · high confidence

**Detects.** The skill reads a credential store — SSH private keys, AWS credentials, kubeconfig, .netrc, .npmrc, a browser credential database, or the system keychain. Confidence is HIGH when a read verb accompanies the path and LOWER when the path is merely mentioned.

**Why it matters.** These files are the keys to everything the user can reach. Reading them is the first stage of the dominant exfiltration pattern in confirmed-malicious skills.

**Fix.** Do not read credential stores. Where a credential is genuinely needed, take it from an environment variable the user has deliberately set for this purpose, and document which one.

**Cannot detect.** Documentation that explains how to configure these files will match at reduced confidence. Check the cited line.

**Taxonomy.** `CWE-522`

**References.** [1](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/), [2](https://cwe.mitre.org/data/definitions/200.html)

### `CRE002` — Hardcoded credential

**high** · high confidence

**Detects.** A string matching the format of a live credential — an API key, personal access token, AWS key id, or PEM private key block — is committed in the skill. Recognised placeholder shapes are excluded.

**Why it matters.** The credential is exposed to everyone with access to the skill, which for a published skill is everyone. Rotation is the only remedy; deletion from the repository is not sufficient because history retains it.

**Fix.** Revoke and rotate the credential now, then remove it from the file and from version-control history. Read it from the environment at runtime instead.

**Cannot detect.** Detects known credential formats only. A high-entropy string in an unrecognised format is not reported, and a realistic-looking example value may be.

**Taxonomy.** `CWE-798`

**References.** [1](https://cwe.mitre.org/data/definitions/798.html)

### `CRE003` — Environment dumped wholesale

**high** · medium confidence

**Detects.** The entire process environment is read or printed, rather than a specific named variable.

**Why it matters.** The environment is where agents hold API keys. Reading all of it collects every secret the process can see, including ones unrelated to the skill's purpose.

**Fix.** Read only the specific variables the skill needs, by name.

**Cannot detect.** Debug tooling and CI helper scripts do this legitimately.

**References.** [1](https://cwe.mitre.org/data/definitions/200.html)

## EVA

**Scanner evasion**

### `EVA001` — Suspicious padding or truncation

**medium** · medium confidence

**Detects.** A file contains a long run of whitespace or repeated filler, or a single line far longer than the rest of the document. Both are used to push content past the window a reviewer reads or a tool truncates.

**Why it matters.** Content positioned after the padding is present in the artifact and read by the model, but is effectively invisible in a diff view or a truncated preview.

**Fix.** Remove the padding and keep lines to a readable length.

**Cannot detect.** Minified assets and generated data files trip this legitimately.

### `EVA002` — Executable or bytecode artifact bundled with the skill

**high** · high confidence

**Detects.** The skill bundles a compiled binary, shared library, or Python bytecode file. This tool does not disassemble them, and neither does a human reviewer.

**Why it matters.** A compiled artifact is unreviewable by inspection. Whatever it does is outside the coverage of this scan and of any code review of the repository.

**Fix.** Ship source, not binaries. If a binary is genuinely required, publish its build provenance and hash so it can be reproduced independently.

**Cannot detect.** SkillSniff does not disassemble binaries, so it reports that the artifact exists and is unanalysed. It cannot tell a benign compiled helper from a malicious one.

### `EVA003` — File content does not match its extension

**high** · high confidence

**Detects.** A file's magic bytes identify it as an archive or binary while its extension claims something else — 'notes.md' that is actually a ZIP, for example.

**Why it matters.** Extension-based tooling, including many scanners and review UIs, will treat the file as text and never inspect what it really contains.

**Fix.** Give the file its correct extension, or remove it.

**Cannot detect.** Identifies archive and common binary formats by magic bytes. A format without a recognised signature, or a file that is genuinely what its extension claims, is not reported.

### `EVA004` — Hidden file or directory in the skill bundle

**low** · medium confidence

**Detects.** The skill bundles dot-prefixed files beyond the conventional set. These are hidden from directory listings and from casual review.

**Why it matters.** Content that a reviewer is unlikely to open, shipped inside the artifact.

**Fix.** Move required configuration to a visible path, or delete the file.

**Cannot detect.** Common dotfiles (.gitignore, .editorconfig) are excluded.

## EXE

**Execution**

### `EXE001` — Remote content piped directly into an interpreter

**critical** · high confidence

**Detects.** A network fetch is piped into a shell or interpreter — the 'curl … | bash' pattern. Detected by tokenising the pipeline, so a quoted or commented example does not match.

**Why it matters.** Whatever the server returns at the moment of execution runs with the agent's full privileges. The content reviewed today is not necessarily the content that runs tomorrow, and the server can serve different content per client.

**Fix.** Download to a file, verify it against a published checksum, review it, then execute. Or vendor the script into the skill so it is reviewable.

**Cannot detect.** Detects pipelines the shell tokeniser can see: bundled scripts, fenced blocks, and decoded regions. A pipeline assembled at runtime from variables is not resolved.

**Taxonomy.** `CWE-494`

**References.** [1](https://cwe.mitre.org/data/definitions/94.html)

### `EXE002` — Decoded content piped into an interpreter

**critical** · high confidence

**Detects.** A decoder (base64, xxd, openssl) feeds its output straight into a shell or interpreter.

**Why it matters.** The executed content is unreadable in the source, so review cannot see what runs. There is no legitimate reason to encode a script that is about to be executed in place.

**Fix.** Inline the script in plain text.

**Cannot detect.** Detects decoder-to-interpreter pipelines lexically. A program that decodes in memory and executes without a pipeline is covered by EXE004 instead, if at all.

**References.** [1](https://cwe.mitre.org/data/definitions/94.html)

### `EXE003` — Shell invoked with an unparsed command string

**high** · high confidence

**Detects.** A subprocess is created with shell=True, or via os.system/os.popen. Detected from the Python AST, so the keyword appearing in a comment or string does not match.

**Why it matters.** Any value interpolated into the command string is interpreted by the shell. If any part of it derives from file contents, a filename, or model output, that is command injection.

**Fix.** Pass an argument list — subprocess.run(['git', 'status']) — which never invokes a shell and needs no quoting.

**Cannot detect.** Python only, from the AST. The equivalent in JavaScript, Ruby, or a shell wrapper is not detected by this rule.

**Taxonomy.** `CWE-78`

**References.** [1](https://cwe.mitre.org/data/definitions/78.html)

### `EXE004` — Dynamic code evaluation

**high** · high confidence

**Detects.** eval, exec, compile, or an equivalent is called on a non-literal value; or pickle/marshal is used to load data. Detected from the AST.

**Why it matters.** Whatever the value evaluates to becomes executable code. pickle.loads on untrusted input is arbitrary code execution by design, not by accident.

**Fix.** Parse data with json or ast.literal_eval. If dispatch is needed, use an explicit mapping of allowed operations.

**Cannot detect.** Python only, from the AST. Dynamic execution in another language, or via a library that evaluates strings internally, is not detected.

**Taxonomy.** `CWE-502`, `CWE-95`

**References.** [1](https://cwe.mitre.org/data/definitions/94.html)

### `EXE005` — Destructive filesystem or database operation

**high** · medium confidence

**Detects.** A recursive delete against a root, home, or wildcard path; a disk-level write; a force-push to a default branch; or a DROP/TRUNCATE statement.

**Why it matters.** Irreversible data loss, executed by an agent that may be running unattended and cannot undo it.

**Fix.** Require explicit user confirmation immediately before the operation, and constrain the target path to a directory the skill created.

**Cannot detect.** A skill that documents these commands as things to avoid will match. Check the cited line before acting.

### `EXE006` — Remote script fetched for execution

**high** · medium confidence

**Detects.** The skill downloads an executable script from a URL that is not pinned to an immutable reference, and executes or sources it.

**Why it matters.** The publisher can change the script after the skill is reviewed and installed. Review establishes nothing about future behaviour.

**Fix.** Pin to a commit SHA or content hash, or vendor the script into the skill.

**Cannot detect.** Requires an execution verb near the URL within a few lines. A download and a later execution separated across files will not correlate.

## EXF

**Exfiltration**

### `EXF001` — Secret value flows to a network sink

**critical** · high confidence

**Detects.** Dataflow analysis of the Python AST found a value originating at an environment read, credential file, or keyring lookup reaching an outbound network call. The flow is followed through assignments, f-strings, containers and concatenation.

**Why it matters.** This is exfiltration: a credential the agent holds is transmitted to a remote party. It is the single highest-severity finding this tool produces because the evidence is behavioural rather than lexical.

**Fix.** Remove the transmission. If a credential must reach a service, it should be sent only to that service's documented endpoint over TLS, and the skill should state plainly which credential goes where.

**Cannot detect.** Intraprocedural and Python-only. A flow that crosses a function boundary, passes through a class attribute, or is written in another language is not tracked here — the pattern-based EXF002 provides weaker coverage for those.

**Taxonomy.** `CWE-201`

**References.** [1](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/), [2](https://cwe.mitre.org/data/definitions/200.html)

### `EXF002` — Secret-shaped value sent to a remote endpoint

**critical** · medium confidence

**Detects.** A network command carries a secret-shaped variable or an environment reference in its payload — for example 'curl -d "$API_TOKEN" https://…'. Requests to localhost, private ranges, and documentation domains are excluded.

**Why it matters.** Credentials leave the machine, to a destination the user has not agreed to.

**Fix.** Remove the credential from the request, or send it only to its own service.

**Cannot detect.** Lexical, so it cannot confirm the variable actually holds a secret. Confidence is MEDIUM for that reason; EXF001 is the higher-assurance version.

**Taxonomy.** `CWE-201`

**References.** [1](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)

### `EXF003` — Data sent to an anonymous or unattributable endpoint

**high** · medium confidence

**Detects.** An upload targets a paste site, anonymous file-drop host, URL shortener, raw IP address, or webhook-relay service.

**Why it matters.** These destinations exist to receive data without attribution. There is no legitimate reason for a skill to send a user's data to one.

**Fix.** Send data only to a named service the user has agreed to, over TLS.

**Cannot detect.** Uses a curated list of paste sites, shorteners, and file-drop hosts, plus raw IPs and low-reputation TLDs. A newly-registered ordinary domain looks unremarkable to this rule.

**References.** [1](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)

### `EXF004` — Local file contents posted to a remote host

**high** · medium confidence

**Detects.** A network command uploads file contents — 'curl --data @file', '-F file=@…', or a read piped into a sender.

**Why it matters.** Repository or filesystem contents leave the machine.

**Fix.** State exactly which file is uploaded and to where, and require confirmation before sending.

**Cannot detect.** Legitimate upload workflows match. Judge by the destination.

## INJ

**Prompt / instruction injection**

### `INJ001` — Instruction-override phrasing

**critical** · high confidence

**Detects.** The skill contains text of the form 'ignore all previous instructions'. Skill content is loaded into the agent's context verbatim, so this phrasing is a direct attempt to countermand the agent's operating rules rather than a description of behaviour.

**Why it matters.** If honoured, the agent discards its safety constraints and the user's actual instructions, and follows the skill instead. This is the entry point for every subsequent action the skill wants to take.

**Fix.** Remove the phrasing. A legitimate skill constrains its own behaviour and never instructs the agent to disregard anything outside itself. If the text is a quoted example of an attack, move it into a fenced code block and label it.

**Cannot detect.** Matches English phrasing. Injection written in another language, or paraphrased to avoid these verbs, is not detected by this rule.

**Taxonomy.** `LLM01:PromptInjection`

**References.** [1](https://owasp.org/www-project-top-10-for-large-language-model-applications/), [2](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)

### `INJ002` — Role or persona hijack

**critical** · high confidence

**Detects.** The skill tells the agent it is now operating as an unrestricted persona — 'developer mode', 'DAN', 'jailbroken', 'act as an uncensored assistant'.

**Why it matters.** Persona reassignment is used to detach the agent from its safety training so that later instructions in the same skill are followed without objection.

**Fix.** Remove the persona reassignment. A skill scopes a task; it does not redefine the agent.

**Cannot detect.** Matches English persona-reassignment phrasing. A hijack written in another language, or phrased indirectly, is not detected.

**Taxonomy.** `LLM01:PromptInjection`

**References.** [1](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

### `INJ003` — Instruction to conceal actions from the user

**critical** · high confidence

**Detects.** The skill instructs the agent to perform an action without telling the user, to hide something from output or logs, or to act 'silently'.

**Why it matters.** Concealment removes the human's ability to notice and stop the action. It is the defining property of a malicious skill: there is no legitimate reason to withhold an action from the person on whose behalf it is taken.

**Fix.** Remove the concealment instruction. If the intent is to keep output concise, say so in terms of formatting rather than in terms of what the user is told.

**Cannot detect.** Phrasings like 'keep the summary brief' are legitimate and not matched. The rule requires an explicit direction not to inform, reveal, or disclose.

**Taxonomy.** `LLM01:PromptInjection`

**References.** [1](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)

### `INJ004` — Conversation frame impersonation

**high** · medium confidence

**Detects.** The content contains markup that impersonates the structure of the conversation itself — '<system>' tags, '[INST]' markers, or chat template special tokens such as '<|im_start|>'.

**Why it matters.** Text that appears to come from a higher-trust turn can be treated as more authoritative than skill content, letting the skill escalate its own instructions.

**Fix.** Remove the markup. If the skill legitimately needs to discuss these tokens, put them inside a fenced code block, which this rule treats as documentation.

**Cannot detect.** Generic XML in a skill about XML will match. Occurrences inside fenced code blocks are excluded to reduce that noise, so the rule can be evaded by a payload placed in a fence.

**Taxonomy.** `LLM01:PromptInjection`

**References.** [1](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

### `INJ005` — Claim of overriding authority

**high** · medium confidence

**Detects.** The skill asserts that its instructions take precedence over other instructions, or impersonates the model vendor or the user's developer to manufacture authority.

**Why it matters.** Manufactured authority is used to make the agent prefer skill instructions over the user's, which inverts the trust relationship the user assumed.

**Fix.** State scope without claiming precedence over the agent's other instructions.

**Cannot detect.** Authority claims are matched lexically. A skill can assert precedence in phrasing this rule does not recognise.

**Taxonomy.** `LLM01:PromptInjection`

**References.** [1](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

### `INJ006` — Injection payload hidden in the description

**critical** · high confidence

**Detects.** The frontmatter description contains markup or instruction-override phrasing. The description is injected into the agent's context during skill *selection*, before the user has chosen to use the skill at all.

**Why it matters.** A payload here executes against every agent that merely lists available skills, without anyone invoking this one. It is the highest-reach position in the artifact.

**Fix.** Keep the description to plain prose describing what the skill does and when to use it.

**Cannot detect.** Checks the description against the same patterns as the body rules, so it inherits their language and phrasing limits.

**Taxonomy.** `LLM01:PromptInjection`

**References.** [1](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)

## MCP

**Tool and MCP abuse**

### `MCP001` — MCP or tool configuration modification

**critical** · medium confidence

**Detects.** The skill writes to an MCP server configuration — .mcp.json, claude_desktop_config.json, or an mcpServers block.

**Why it matters.** Adding an MCP server grants the agent a new set of tools from a new source, permanently and for every project. It is equivalent to installing software with the agent's full trust.

**Fix.** Do not modify tool configuration. Document the server and let the user install it.

**Cannot detect.** Requires a write verb near the configuration path. A skill that documents an MCP configuration without writing it matches at reduced confidence; one that writes it through an indirection does not match.

**Taxonomy.** `LLM01:PromptInjection`

### `MCP002` — Undeclared tool invocation

**medium** · low confidence

**Detects.** The body instructs the agent to use a tool that is not listed in 'allowed-tools'. Only reported when the skill declares allowed-tools at all, since an absent declaration means 'unrestricted' rather than 'none'.

**Why it matters.** The declared tool list is what a reviewer or policy engine uses to reason about the skill's reach. A skill using tools outside it has a wider surface than its declaration suggests.

**Fix.** Add the tool to allowed-tools, or stop using it.

**Cannot detect.** Tool names are matched lexically in prose, so a skill discussing a tool by name without using it can match.

### `MCP003` — Overly broad tool declaration

**medium** · medium confidence

**Detects.** 'allowed-tools' grants unrestricted shell access (a bare 'Bash' with no command scoping) or uses a bare wildcard.

**Why it matters.** Unscoped shell access is every capability at once: filesystem, network, process execution, credential access. No further restriction applies.

**Fix.** Scope the grant to the commands actually needed, e.g. 'Bash(git status:*)'.

**Cannot detect.** Some agent platforms do not support scoped tool grants.

## MEM

**Memory and state**

### `MEM001` — Agent instruction file modification

**critical** · medium confidence

**Detects.** The skill writes to a file that provides standing instructions to the agent — CLAUDE.md, AGENTS.md, .cursorrules, a memory file, or an agent settings file.

**Why it matters.** The skill is rewriting the agent's own instructions. Content placed there is loaded in every future session as trusted context, which converts a single execution into permanent influence over the agent.

**Fix.** A skill should not write to the agent's instruction files. If the user wants persistent guidance, they should add it deliberately.

**Cannot detect.** A skill whose stated purpose is managing these files (a memory-management or project-scaffolding skill) will match legitimately.

**Taxonomy.** `LLM01:PromptInjection`

### `MEM002` — Instruction to persist information across sessions

**medium** · low confidence

**Detects.** The instruction body tells the agent to remember something for future sessions.

**Why it matters.** Cross-session state that the user did not ask for changes the agent's behaviour later, at a point where the cause is no longer visible.

**Fix.** State explicitly what is stored, where, and how the user removes it.

**Cannot detect.** Many skills legitimately maintain state. This is informational and should not on its own be treated as a defect.

## NET

**Network behaviour**

### `NET001` — Mutable external reference

**low** · high confidence

**Detects.** The skill references remote content that is not pinned — a branch URL, a bare domain, or a 'latest' link.

**Why it matters.** What the reference resolves to can change after the skill is reviewed.

**Fix.** Pin to a commit SHA or a versioned release URL.

**Cannot detect.** Documentation links are matched too. This rule is informational by design; EXE006 and SUP005 carry the higher severity where the content is executed or obeyed.

### `NET002` — Hardcoded IP address endpoint

**medium** · medium confidence

**Detects.** A network endpoint is written as a raw IP address. Private ranges and localhost are excluded as ordinary development references.

**Why it matters.** A literal IP has no certificate identity and no DNS reputation, and it survives domain takedown. It is common in payload infrastructure.

**Fix.** Use a hostname over TLS, or remove the endpoint.

### `NET003` — Plaintext HTTP endpoint

**low** · high confidence

**Detects.** A resource is fetched over http:// rather than https://.

**Why it matters.** Content can be observed and modified in transit by any intermediary.

**Fix.** Use https:// so the content cannot be observed or altered in transit.

**Cannot detect.** Localhost and private-range URLs are excluded.

## OBS

**Obfuscation**

### `OBS001` — Invisible characters in skill content

**high** · high confidence

**Detects.** Zero-width spaces, joiners, soft hyphens and similar formatting characters render as nothing to a human but are part of the token stream the model reads. They are used both to hide instructions and to break up keywords so that a literal-matching scanner misses them.

**Why it matters.** A reviewer approves text that differs from what the agent acts on. Every other control in the review process is built on the assumption those are the same.

**Fix.** Strip the characters. If a specific one is genuinely required (a soft hyphen in typeset prose, a ZWJ in an emoji sequence), keep it and suppress this rule for that path rather than repository-wide.

**Cannot detect.** Legitimate uses exist in non-Latin scripts and emoji sequences, so this rule reports position and character rather than asserting malice.

**References.** [1](https://trojansource.codes/)

### `OBS002` — Bidirectional control characters

**critical** · high confidence

**Detects.** Bidi overrides and isolates (U+202A–U+202E, U+2066–U+2069) reorder how text is displayed without changing its logical order. The rendered line a reviewer reads can be arbitrarily different from the line that is executed.

**Why it matters.** The 'Trojan Source' class of attack: a command can be displayed as a comment, or a condition displayed inverted, with the real behaviour invisible in review.

**Fix.** Remove the control characters entirely.

**Cannot detect.** Reports the presence of bidi control characters. It does not render the text both ways to show what a reviewer would have seen versus what executes.

**References.** [1](https://trojansource.codes/)

### `OBS003` — Instructions hidden in Unicode tag characters

**critical** · high confidence

**Detects.** The Unicode Tag block (U+E0000–U+E007F) mirrors ASCII, renders as nothing in essentially every client, and survives copy-paste. This rule decodes any tag run back to the ASCII it carries.

**Why it matters.** A complete instruction set can be carried invisibly inside otherwise innocuous text. Nothing in a normal review workflow surfaces it.

**Fix.** Remove every code point in the U+E0000–U+E007F range.

**Cannot detect.** Decodes the Unicode Tag block only. Other invisible channels are covered by OBS001, and a channel this tool does not know about would not be reported at all.

**References.** [1](https://trojansource.codes/)

### `OBS004` — Homoglyph or mixed-script evasion

**medium** · medium confidence

**Detects.** A word mixes scripts and contains a character that looks like an ASCII letter — Cyrillic 'с' for Latin 'c', for example. This defeats literal keyword matching while reading identically to a human.

**Why it matters.** Keyword-based controls (scanners, allowlists, review filters) miss the term while the model still resolves the meaning from context.

**Fix.** Replace the non-ASCII lookalikes with their ASCII equivalents.

**Cannot detect.** Uses a curated homoglyph table covering the Cyrillic, Greek, Armenian and fullwidth lookalikes seen in practice, not the complete UTS #39 confusables set. Genuine multilingual prose is not flagged: the rule requires script mixing *within a single word*.

**References.** [1](https://www.unicode.org/reports/tr39/)

### `OBS005` — Encoded payload with executable or credential content

**critical** · high confidence

**Detects.** A base64, hex, percent- or escape-encoded region decodes to content containing shell commands, network fetches, credential references, or injection phrasing. Decoding is recursive, so a payload wrapped twice is still resolved.

**Why it matters.** Encoding is how a payload is carried past both human review and pattern-based scanning. Content that has to be decoded before it makes sense was hidden on purpose.

**Fix.** Inline the content in plain text so it can be reviewed. If the data is legitimately binary, document what it is and why it must be embedded.

**Cannot detect.** Only reports decoded regions whose content looks executable or credential-related; an encoded payload of pure natural language is reported by OBS006 at lower severity. Encryption, rather than encoding, is not recoverable and is reported as a coverage gap instead.

**References.** [1](https://trojansource.codes/)

### `OBS006` — Large encoded region

**low** · medium confidence

**Detects.** A substantial encoded blob is present whose decoded content is not obviously executable. Reported for visibility rather than as a defect.

**Why it matters.** Encoded content cannot be reviewed by reading the file, so it is a blind spot in any review that does not decode it.

**Fix.** Inline the content in plain text, or document what the blob is.

**Cannot detect.** Embedded images and test fixtures legitimately look like this.

## PER

**Persistence**

### `PER001` — Shell profile modification

**critical** · medium confidence

**Detects.** The skill writes to a shell startup file (.bashrc, .zshrc, .profile and similar). Requires both a profile path and a write verb nearby.

**Why it matters.** Anything added there executes on every future shell the user opens, indefinitely, with no further involvement from the skill or the agent. It survives uninstalling the skill.

**Fix.** Do not modify shell startup files. If the user needs an environment change, print the line and let them add it themselves.

**Cannot detect.** Documentation showing a line to add will match. Check the cited line.

**Taxonomy.** `MITRE-T1546`

### `PER002` — Scheduled task or autostart registration

**critical** · medium confidence

**Detects.** The skill registers a cron job, systemd unit, launch agent, Windows Run key, scheduled task, or Git hook.

**Why it matters.** Code runs on a schedule or on an event, independent of the agent and outside any session the user is watching.

**Fix.** Do not install background execution. Perform work in the foreground when invoked.

**Cannot detect.** Matches known scheduler and autostart mechanisms across Linux, macOS and Windows. A platform-specific mechanism outside that set is not detected.

**Taxonomy.** `MITRE-T1053`

## PRV

**Privilege and safety bypass**

### `PRV001` — Agent safety controls disabled

**critical** · high confidence

**Detects.** The skill instructs the agent, or configures a tool, to skip permission prompts, auto-approve actions, or run without a sandbox — for example '--dangerously-skip-permissions', 'bypassPermissions', or 'autoApprove: true'.

**Why it matters.** The user's ability to review and refuse individual actions is removed. Every other capability the skill has becomes unsupervised.

**Fix.** Remove the flag. A skill must never widen the agent's permissions on the user's behalf; that decision belongs to the user.

**Cannot detect.** Matches known agent and tool flags. A future flag, or a configuration file that disables permissions without using one of these names, is not detected.

### `PRV002` — Transport security disabled

**high** · high confidence

**Detects.** TLS verification is turned off: 'curl -k', 'verify=False', 'NODE_TLS_REJECT_UNAUTHORIZED=0', or 'rejectUnauthorized: false'.

**Why it matters.** Any network position between the agent and the server can substitute content or capture what is sent, including credentials.

**Fix.** Leave verification enabled. For a private CA, install the certificate rather than disabling the check.

**Cannot detect.** Covers common HTTP clients and CLI tools. A custom TLS context configured through a less common API is not detected.

**Taxonomy.** `CWE-295`

**References.** [1](https://cwe.mitre.org/data/definitions/295.html)

### `PRV003` — Privilege escalation via sudo or setuid

**high** · medium confidence

**Detects.** The skill runs commands under sudo/doas, or sets the setuid bit.

**Why it matters.** Actions execute with administrative privilege, outside anything the agent's own sandbox can constrain.

**Fix.** Operate at the user's own privilege level. If elevation is genuinely required, state it prominently and require explicit confirmation.

**Cannot detect.** Installation documentation legitimately mentions sudo.

## QUA

**Authoring quality**

> Findings in this family are reported separately and never affect the security verdict.

### `QUA001` — Skill body is too long

**medium** · high confidence

**Detects.** The body exceeds 5000 words or 500 lines.

**Why it matters.** The entire body loads into context every time the skill triggers, displacing the user's actual task and degrading the agent's attention across it.

**Fix.** Move detail into references/ files the agent loads only when needed.

**Cannot detect.** A word count is a proxy for context cost, not a measure of whether the content earns its place.

**Taxonomy.** `LSB`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA002` — Detail not delegated to reference files

**low** · medium confidence

**Detects.** The body exceeds 1500 words with no references/ directory.

**Why it matters.** Low-level detail is loaded unconditionally instead of on demand.

**Fix.** Move detail into references/ and link to it from the body.

**Cannot detect.** Some long skills legitimately have no separable detail.

**Taxonomy.** `UD`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA003` — Description does not convey a capability

**medium** · high confidence

**Detects.** The skill's name is a generic word such as 'helper', 'utils', or 'run'.

**Why it matters.** The agent routes to skills by name and description. A name conveying no capability cannot be matched to a task, so the skill is never selected.

**Fix.** Name the action and the object, e.g. 'threat-model-review'.

**Cannot detect.** Uses a fixed list of generic names; an unusual but equally vague name is not caught.

**Taxonomy.** `USN`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA004` — Description is not in the third person

**low** · medium confidence

**Detects.** The description uses first or second person outside quoted trigger phrases.

**Why it matters.** Mixed point of view hurts retrieval, because descriptions are matched against task statements written in the third person.

**Fix.** Write 'Reviews X and reports Y', not 'I review X' or 'You can use this to'.

**Cannot detect.** Quoted spans are excluded, since a quoted user utterance is correctly first-person.

**Taxonomy.** `NTPD`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA005` — XML-style tags in the description

**medium** · high confidence

**Detects.** The frontmatter description contains XML-style tags such as <note> or <important>. The description is concatenated into the agent's context during skill selection, so markup there is interpreted rather than displayed.

**Why it matters.** Description text is injected into the agent's prompt during skill selection; markup there is a known injection vector. INJ006 covers the malicious case, this rule the merely careless one.

**Fix.** Remove the tags and write plain prose.

**Cannot detect.** A skill legitimately about XML will match.

**Taxonomy.** `XID`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA006` — Workflow has no ordered steps

**medium** · medium confidence

**Detects.** A body over 250 words describes a procedure as prose with no numbered steps.

**Why it matters.** The agent cannot track its position in an unordered procedure, and the author cannot tell where it went wrong.

**Fix.** Decompose the procedure into numbered steps.

**Cannot detect.** Reference material that is not a procedure will match; consider suppressing per path.

**Taxonomy.** `TSW`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA007` — No validation step

**medium** · medium confidence

**Detects.** The body contains no instruction to verify the work before declaring it done.

**Why it matters.** One-shot generation with no feedback loop is the most common cause of confidently wrong output.

**Fix.** Add an explicit check the agent must run before finishing.

**Cannot detect.** Detects validation *vocabulary*. Deliberately excludes bare 'review' and 'test', which are domain nouns in review and testing skills and would produce false negatives on exactly the skills that most need this rule.

**Taxonomy.** `NVS`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA008` — No mechanism to ask the user

**low** · medium confidence

**Detects.** The body never tells the agent when to stop and ask rather than assume.

**Why it matters.** The agent guesses at ambiguity instead of resolving it, and the user finds out after the work is done.

**Fix.** State the conditions under which the agent should stop and ask.

**Cannot detect.** Lexical proxy; a skill may express this in unrecognised phrasing.

**Taxonomy.** `NAH`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA009` — Nothing prevents skipping a required step

**medium** · medium confidence

**Detects.** No language marks any step as non-skippable.

**Why it matters.** Agents rationalise their way out of steps that are merely listed. The source study found this the most common smell in the wild.

**Fix.** Mark the steps that must not be skipped and say so explicitly.

**Cannot detect.** Presence of the phrasing does not guarantee the agent honours it.

**Taxonomy.** `RL`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA010` — No progress tracking for a long procedure

**low** · medium confidence

**Detects.** Five or more steps with no checklist or progress mechanism.

**Why it matters.** Long procedures drift without a way for the agent to mark position.

**Fix.** Give the agent a checklist to mark off.

**Cannot detect.** Counts ordered list items, which under-counts procedures written as headings.

**Taxonomy.** `NPT`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA011` — No guardrails

**medium** · medium confidence

**Detects.** The body never states what the skill should not do.

**Why it matters.** Without stated limits the agent applies the skill outside its competence and produces confident output in situations the author never considered.

**Fix.** State the out-of-scope cases and what to do when the task is inappropriate.

**Cannot detect.** Lexical proxy for the presence of constraints.

**Taxonomy.** `NG`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA012` — No caveats or failure modes documented

**low** · medium confidence

**Detects.** The body documents no gotchas, limitations, or failure modes.

**Why it matters.** The agent has no way to recognise that the situation is one the skill handles badly.

**Fix.** Document what commonly goes wrong and how to resolve it.

**Cannot detect.** Lexical proxy.

**Taxonomy.** `MC`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA013` — Warning text is not visually marked

**low** · low confidence

**Detects.** A line containing warning vocabulary carries no bold, blockquote, heading, or code formatting.

**Why it matters.** Unmarked warnings are skimmed past by both humans and models.

**Fix.** Put warnings in a bold line, a blockquote, or their own heading.

**Cannot detect.** Formatting is a weak proxy for salience.

**Taxonomy.** `BG`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA014` — No worked example

**medium** · medium confidence

**Detects.** The body contains neither the word 'example' nor a fenced code block.

**Why it matters.** Examples are the highest-leverage content in a skill; without one the agent infers the expected shape of the work from the prose alone.

**Fix.** Include at least one concrete input/output pair.

**Cannot detect.** Presence of a code fence is taken as evidence of an example, which over-counts.

**Taxonomy.** `ME`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA015` — Time-sensitive content

**low** · medium confidence

**Detects.** The body contains statements pinned to a moment in time.

**Why it matters.** The content silently becomes wrong, and neither agent nor user can tell when.

**Fix.** Remove the time-pinned statement, or move it to a reference file with a review date.

**Cannot detect.** Matches a fixed set of phrasings.

**Taxonomy.** `TSS`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA016` — Output format described but not shown

**low** · medium confidence

**Detects.** The body describes an output format without giving a template.

**Why it matters.** The agent invents a format, and output varies between runs.

**Fix.** Show the exact shape of the expected output in a fenced block.

**Cannot detect.** Lexical proxy.

**Taxonomy.** `MT`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA017` — File paths use backslashes

**low** · high confidence

**Detects.** Paths in the body use Windows-style backslash separators.

**Why it matters.** Agents traverse the skill directory as a POSIX filesystem; backslash paths do not resolve.

**Fix.** Rewrite the paths with forward slashes, which resolve on every platform the agent runs on.

**Cannot detect.** An escaped character in prose can match.

**Taxonomy.** `BP`

**References.** [1](https://arxiv.org/abs/2607.01456)

### `QUA018` — No explicit usage rules

**low** · low confidence

**Detects.** The body has no section stating rules, constraints, or principles.

**Why it matters.** The agent has no stated standard to hold itself to.

**Fix.** Add a short rules section stating the non-negotiable constraints.

**Cannot detect.** Weak structural proxy; many good skills express rules without a dedicated heading.

**Taxonomy.** `MUR`

**References.** [1](https://arxiv.org/abs/2607.01456)

## SPEC

**Specification compliance**

> Findings in this family are reported separately and never affect the security verdict.

### `SPEC001` — Malformed or missing frontmatter

**high** · high confidence

**Detects.** SKILL.md must open with a YAML frontmatter block delimited by '---' on the very first line. This rule reports a missing block, an unterminated block, content before the opening fence, invalid YAML, and a frontmatter block that is not a mapping.

**Why it matters.** Loaders that cannot parse the frontmatter skip the skill entirely. The skill appears installed but never activates, with no error shown to the user.

**Fix.** Start the file with '---' at byte 0, close the block with '---', and ensure the contents parse as a YAML mapping of key/value pairs.

**Cannot detect.** Without PyYAML installed a small number of exotic YAML constructs are reported as unparseable lines rather than parsed. Install the 'yaml' extra for full fidelity.

**References.** [1](https://agentskills.io/specification)

### `SPEC002` — Missing required field

**high** · high confidence

**Detects.** The specification requires both 'name' and 'description' in frontmatter.

**Why it matters.** A skill with no name cannot be addressed; a skill with no description has no trigger condition and will never be selected by the agent.

**Fix.** Add the missing field to the frontmatter block.

**References.** [1](https://agentskills.io/specification)

### `SPEC003` — Invalid name format

**high** · high confidence

**Detects.** 'name' must be lowercase letters, digits, and single interior hyphens: no uppercase, underscores, spaces, leading or trailing hyphens, or consecutive hyphens.

**Why it matters.** Loaders reject or mis-resolve names outside this grammar.

**Fix.** Rewrite the name as lowercase hyphen-separated words, e.g. 'threat-model-review'.

**References.** [1](https://agentskills.io/specification)

### `SPEC004` — Name does not match its directory

**medium** · high confidence

**Detects.** The 'name' field should match the directory containing SKILL.md, because loaders resolve skills by directory.

**Why it matters.** The skill is discovered under a name nothing references, so documentation, marketplace entries, and cross-skill references all point at nothing.

**Fix.** Rename the directory or the 'name' field so the two agree.

**References.** [1](https://agentskills.io/specification)

### `SPEC005` — Field exceeds its length limit

**medium** · high confidence

**Detects.** 'name' is limited to 64 characters, 'description' to 1024, and 'compatibility' to 500.

**Why it matters.** Over-long fields are truncated or rejected, changing or disabling the trigger.

**Fix.** Move detail into the body; frontmatter is for routing, not documentation.

**References.** [1](https://agentskills.io/specification)

### `SPEC006` — Unknown frontmatter key

**low** · high confidence

**Detects.** Only name, description, license, allowed-tools, metadata and compatibility are defined at the top level. 'metadata' is the extension point for anything else.

**Why it matters.** Unknown keys are ignored by conforming loaders, so any behaviour the author expected from them silently does not happen.

**Fix.** Move the key under 'metadata:'.

**References.** [1](https://agentskills.io/specification)

### `SPEC007` — Empty or missing body

**medium** · high confidence

**Detects.** A skill whose SKILL.md has no body after the frontmatter carries no instructions.

**Why it matters.** The skill adds its description to the agent's context and nothing else.

**Fix.** Write the procedure the skill is supposed to encode.

**References.** [1](https://agentskills.io/specification)

### `SPEC008` — Field has the wrong type

**medium** · high confidence

**Detects.** 'name', 'description' and 'license' must be strings; 'allowed-tools' a list of strings (a comma-separated string is tolerated by most loaders but is not the specified form); 'metadata' and 'compatibility' mappings.

**Why it matters.** A mistyped field is ignored or crashes the loader, disabling the skill.

**Fix.** Correct the value's type to match the specification.

**References.** [1](https://agentskills.io/specification)

### `SPEC009` — Description does not state when to use the skill

**medium** · medium confidence

**Detects.** The description is the only text the agent sees when deciding whether to load a skill. It needs to say what the skill does *and* the conditions under which it applies. This rule looks for trigger phrasing such as 'use when'.

**Why it matters.** Without a trigger condition the agent cannot route to the skill reliably; it loads at the wrong times or not at all.

**Fix.** Use the shape: [what it does] + [when to use it] + [keywords the user would say].

**Cannot detect.** This is a lexical proxy. A description can state a trigger in phrasing this rule does not recognise, and can contain the phrase 'use when' while saying nothing useful.

**Taxonomy.** `CSD`

**References.** [1](https://agentskills.io/specification), [2](https://arxiv.org/abs/2607.01456)

### `SPEC010` — Referenced file does not exist

**medium** · high confidence

**Detects.** The body points the agent at a bundled file (for example 'references/stride.md') that is not present in the skill directory.

**Why it matters.** The agent is told to load context that does not exist. In practice it either stops, or proceeds without the material and fabricates the missing content.

**Fix.** Add the file, or remove the reference.

**Cannot detect.** Only resolves relative paths that appear in Markdown links or backticks.

**References.** [1](https://agentskills.io/specification)

## SUP

**Supply chain**

### `SUP001` — Unpinned dependency

**medium** · high confidence

**Detects.** A dependency is declared with a version range, a moving tag, or no constraint at all, so resolution picks whatever is newest at install time.

**Why it matters.** The code that runs is not the code that was reviewed. A compromise of the upstream package, or of the maintainer's account, reaches this skill automatically and without any change to this repository.

**Fix.** Pin to an exact version, and to an artifact hash where the ecosystem supports it (pip --hash, npm lockfile integrity).

**Taxonomy.** `CWE-1357`

**References.** [1](https://slsa.dev/)

### `SUP002` — Install-time script hook

**high** · high confidence

**Detects.** package.json declares a preinstall, install, postinstall, or prepare script. These execute automatically when dependencies are installed.

**Why it matters.** Code runs before anyone has chosen to run anything, and before any review of the installed tree. This is the primary npm supply-chain execution vector.

**Fix.** Remove the hook and perform the work explicitly at a point the user controls.

**Cannot detect.** npm lifecycle hooks only. The equivalent in other ecosystems (setup.py build hooks, Cargo build scripts, Gradle tasks) is not yet parsed.

**References.** [1](https://slsa.dev/)

### `SUP003` — Dependency fetched from a VCS branch

**medium** · high confidence

**Detects.** A dependency points at a Git repository without a commit pin, so it tracks whatever the branch currently holds.

**Why it matters.** The dependency's contents can change at any time with no version bump to notice.

**Fix.** Pin the dependency to a full commit SHA.

**References.** [1](https://slsa.dev/)

### `SUP004` — Package installed at runtime

**high** · medium confidence

**Detects.** The skill instructs the agent to install a package while it runs, rather than declaring it as a dependency.

**Why it matters.** Runtime installation bypasses lockfiles, review, and any dependency scanning the project has. A typosquatted or newly-compromised package is pulled in silently.

**Fix.** Declare dependencies in a manifest so they are visible, pinnable, and scannable.

**Cannot detect.** Matches installer command lines. A skill that installs a package through a library call rather than a command is not detected by this rule.

**References.** [1](https://slsa.dev/)

### `SUP005` — Skill fetches its instructions from a remote source

**critical** · medium confidence

**Detects.** The skill directs the agent to retrieve instructions, rules, prompts, or configuration from a URL at runtime and act on them.

**Why it matters.** The skill's real behaviour lives at the far end of that URL and can be changed at any time by whoever controls it. Reviewing this skill tells you nothing about what it will instruct the agent to do.

**Fix.** Vendor the instructions into the skill so they are versioned and reviewable. If remote content is essential, pin it by content hash and verify before use.

**Cannot detect.** Matches English phrasing that describes fetching instructions. A skill that fetches remote content without describing it in these terms is reported by NET001 at much lower severity instead.

**Taxonomy.** `LLM01:PromptInjection`

**References.** [1](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
