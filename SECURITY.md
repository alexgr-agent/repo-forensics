# Security Policy

repo-forensics is a security tool, so a flaw in it matters twice: once for the
code it fails to catch, and once for the machine it runs on. We take both
seriously.

## Reporting a vulnerability

Please report privately. Do not open a public issue for a security problem.

- **GitHub:** [Report a vulnerability](https://github.com/alexgreensh/repo-forensics/security/advisories/new) (private advisory)
- **Email:** me@alexgreenshpun.com

Please include what you found, how to reproduce it, and what an attacker could
do with it. A proof of concept helps, but is not required.

**Response times**

| Step | Target |
|------|--------|
| Acknowledge your report | 48 hours |
| Confirm or rule out the issue | 7 days |
| Fix or mitigation for critical issues | 7 days after confirming |

We credit reporters in the release notes and advisory, unless you prefer to
stay anonymous.

**Safe harbor.** Good-faith research on your own machine and your own copies of
repo-forensics is welcome. We will not pursue legal action for research that
follows this policy, avoids harm to other people's data and systems, and gives
us a reasonable chance to fix the issue before you publish.

## What counts

In scope:

- **Code execution or data access through the scanner itself.** A scanned repo
  that makes repo-forensics run its code, read files outside the target, or
  send data anywhere.
- **Detection bypasses** for attack classes the README says we catch.
- **Trust-chain flaws.** Ways around the signed release manifest, the signed
  rule-pack and IOC feeds, their version floors, or `--verify-install`.
- **Hooks and the background refresh job.** Anything that lets them block
  work, run untrusted code, or change files they shouldn't.
- **Network promises.** Any outbound call that `--offline` does not stop, or
  any data sent beyond what the README's network table lists.
- **The GitHub Action** (`action.yml`) and the IOC and rule-pack data.

Out of scope:

- Vulnerabilities in repositories that repo-forensics scans (report those to
  their owners).
- False positives. Please open a regular issue for those.
- Findings that need an attacker who already controls your machine or your
  copy of repo-forensics. `--verify-install` exists to catch the second case.

## Verifying what you run

You don't need to trust us. You can check:

```bash
python3 skills/repo-forensics/scripts/verify_install.py --verify-signature
python3 skills/repo-forensics/scripts/verify_install.py --verify
```

The pinned Ed25519 public keys are:

| Key | Public key |
|-----|------------|
| Release manifest (`checksums.json.sig`) | `c86f717c5f3293da397435cde3d8ab49cddba2165eddbd47c6fb62aad3e9526a` |
| Rule-pack feed | `a6529e80619abaf38bec2b15154ca8f540f9a830e310f1a0c7a6771e85f1b76c` |

The private keys are held offline and never stored in this repository. A key
change only ever ships inside a signed release and is announced in the release
notes. A key that changes any other way is a red flag, so please report it.

For the full picture (offline mode, the network table, sandboxing, and what
runs in the background), see
[Can you trust repo-forensics?](README.md#can-you-trust-repo-forensics)

## Supported versions

Only the latest release gets security fixes. Update before reporting, and
check that `--verify-install` passes, so we know which code you're running.
