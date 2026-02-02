# security-review

A Claude Code skill that forces a mandatory security review gate on every plan and code output. No code ships without being threat modeled, attack-emulated, mitigated, and pen tested.

## What It Does

This skill turns Claude Code into a security-conscious reviewer with CompTIA Security+ level knowledge. Every time Claude produces a plan, writes code, designs architecture, or modifies infrastructure, it must pass through a 7-step security workflow before delivery:

1. **Plan Review** — Evaluate the plan against an 80+ item security checklist covering authentication, authorization, input validation, cryptography, secrets management, logging, privacy, infrastructure, dependencies, deployment, and availability.
2. **Threat Model** — Identify assets, trust boundaries, entry points, threat actors, and concrete numbered attack paths with risk ratings.
3. **Secure Implementation** — Write code with security controls baked in from line one. Default-deny, parameterized queries, fail-closed errors, least privilege, encryption, and more as non-negotiable defaults.
4. **Attack Emulation** — Agentically walk each attack path from the threat model through the actual code, tracing payloads from entry point to dangerous sink, and verdict each path as BLOCKED or VULNERABLE.
5. **Mitigate** — Fix every VULNERABLE finding, then re-emulate until all paths are BLOCKED.
6. **Pen Test** — Final pass re-running all attack paths plus bonus checks for race conditions, TOCTOU, deserialization, path traversal, integer overflow, and dependency confusion.
7. **Deliver** — Only after all steps pass. Output includes a security summary with attack paths analyzed, controls implemented, and residual risks noted.

A lightweight mode exists for trivial code with no attack surface (pure formatting functions, etc.) so it doesn't slow you down when it doesn't need to.

## What's Inside

```
security-review/
├── SKILL.md                                  # Core skill definition and 7-step workflow
├── references/
│   ├── security-checklist.md                 # 80+ item checklist across 12 categories
│   ├── anti-patterns.md                      # ~30 named anti-patterns from real breaches
│   └── attack-emulation-guide.md             # Per-vulnerability-class emulation methodology
├── README.md
├── LICENSE
└── .gitignore
```

### Reference Files

- **security-checklist.md** — The checklist applied in Step 1. Covers authentication, authorization, input validation, output encoding, cryptography, secrets management, error handling, data protection, network/infrastructure, dependencies, deployment, and availability.
- **anti-patterns.md** — A catalog of recurring security disasters drawn from real-world breaches (Equifax, Capital One, Uber, Adobe, Target, and more), organized by category with identifiers like `AP-AUTH-01`, `AP-INJ-01`, etc. If Claude recognizes one of these patterns in your code, it stops and fixes it.
- **attack-emulation-guide.md** — Concrete methodology for emulating attacks per vulnerability class: injection, authentication, authorization, data exposure, infrastructure, and logic flaws. Includes specific payloads to trace and verdict criteria.

## Installation

Copy the `security-review` directory into your Claude Code skills folder:

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/security-review.git

# Copy into your Claude Code skills directory
cp -r security-review /path/to/your/claude-code/skills/
```

Or if you prefer the `.skill` package format, zip the directory:

```bash
cd security-review
zip -r ../security-review.skill SKILL.md references/
```

## How This Was Created

This skill was built in a conversation with Claude using Anthropic's [skill-creator](https://docs.anthropic.com/) tooling. The process:

1. **Defined the philosophy** — The guiding prompt was essentially: *"You've read the Security+ book and have the knowledge and experience of a cyber security intern. Since the LLM has already ingested the entire Internet of both bad and good content, use every repeating disaster you've managed to tokenize to predict the next one and avoid these anti-patterns. Threat model the code you produce, leverage agentic capabilities to emulate attack paths, mitigate them, and pen test again before you set it free on the world."*
2. **Structured the workflow** — Translated that philosophy into a concrete 7-step sequential workflow that Claude must follow on every qualifying task, with explicit gate conditions (all paths must return BLOCKED before delivery).
3. **Built the reference library** — Created three reference files to give the workflow teeth: a comprehensive checklist, a catalog of real-world anti-patterns, and a per-vulnerability emulation guide. These are loaded progressively — Claude only reads what it needs for the current step.
4. **Validated and packaged** — Used the skill-creator's validation and packaging scripts to ensure the skill meets all structural requirements.

The intent is that Claude can't just *say* it reviewed security — the workflow forces it to show its work at every step, with concrete attack paths, concrete verdicts, and concrete mitigations.

## Contributing

PRs welcome. Particularly useful additions:

- New anti-patterns from recent breaches
- Language-specific or framework-specific emulation payloads
- Expanded checklist items for cloud-native, mobile, or IoT contexts
- Real-world test cases that exercise the workflow

## License

MIT — see [LICENSE](LICENSE).
