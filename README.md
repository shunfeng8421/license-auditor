# License Auditor ⚖️🔍

**GPL contamination detector for open source dependencies. Zero LLM tokens.**

## Quick Start
```bash
python auditor.py --dir /path/to/project/
```

## What It Checks
| Check | Severity | What It Looks For |
|-------|----------|-------------------|
| GPL dependency in MIT project | critical | GPL/LGPL/AGPL packages |
| License header missing | medium | Missing LICENSE file |
| Conflicting licenses | high | MIT + GPL incompatibility |

## Why It Matters
GPL is "viral" — if your MIT/Apache/BSD project depends on a GPL library, you may be forced to release your entire project under GPL. This auditor catches contamination before you ship.

## Verified On
Flask, requests, temporal — real-world dependency trees.

Star ⭐ to protect your open source license.
