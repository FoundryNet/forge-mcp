# Security policy

**Forge by Foundry Labs** · Foundry Labs LLC

## Reporting a vulnerability

Email **foundrynet@proton.me**.

Put `SECURITY` in the subject line. Please include:

- what you found, and the component (`forge.foundrynet.io`, `mcp.foundrynet.io`,
  `ghcr.io/foundrynet/forge-kernel`, `ghcr.io/foundrynet/forge-sandbox`, or a repository name)
- the steps to reproduce it, and what you observed versus what you expected
- the commit, image digest or corpus version you tested against, if you know it
- whether you believe the issue is already public

Do **not** email `forge@foundrynet.io`. That address is send-only: outbound mail from it is
DKIM-signed and delivers, but **inbound mail to it bounces**. A security contact that
silently bounces is worse than none, which is why it is called out here.

We do not currently operate a bug bounty and cannot offer payment.

## What to expect

These are commitments about *communication*, not about repair time. Foundry Labs is a small
company and will not pretend to a response schedule it cannot staff.

| stage | target |
|---|---|
| Acknowledgement that a human has read your report | **3 business days** |
| An initial assessment: reproduced / not reproduced / need more information, and a severity | **10 business days** |
| Regular updates while the issue is open | at least every **14 days** |
| Credit in the fix note, if you want it | on request |

If you have not heard anything in 5 business days, resend — assume the mail was lost rather
than ignored.

## Coordinated disclosure

We ask for **90 days** from acknowledgement before public disclosure, and we will publish a
fix note when the fix ships. If a fix will take longer than 90 days we will tell you why and
propose a date rather than ask for open-ended silence. If the issue is being actively
exploited, we will move as fast as we can and we will not ask you to wait.

You are welcome to disclose on your own schedule. We would rather know late than not know.

## Safe harbour

If you make a good-faith effort to follow this policy, Foundry Labs will not initiate or
support legal action against you for your research. Good faith means:

- confining your testing to assets you own, or to `ghcr.io/foundrynet/forge-sandbox`,
  which is public and exists for exactly this purpose
- not accessing, modifying, exfiltrating or retaining data belonging to another tenant
- not degrading service for others — no load testing, no denial of service, no spam
- stopping as soon as you have established the issue, and telling us rather than going further

This paragraph is a statement of how Foundry Labs intends to behave. It is not legal advice
to you, and it cannot bind a third party such as our hosting providers.

## Scope

**In scope**

- `forge.foundrynet.io` (cloud API)
- `mcp.foundrynet.io` (MCP server)
- `protect.foundrynet.io`, `foundrynet.io` (web)
- `ghcr.io/foundrynet/forge-kernel` and `ghcr.io/foundrynet/forge-sandbox` (published images)
- the public corpus at `github.com/FoundryNet/canonical-schema`

**Out of scope**

- third-party platforms we build on (Railway, Supabase, Cloudflare, GitHub, Netlify,
  Stripe, Resend) — report those to the platform; tell us too if it affects Forge
- findings that depend on a licensee's own deployment, network or bridge
- missing hardening headers, rate-limit tuning and version disclosure, absent a demonstrated
  impact
- social engineering of Foundry Labs staff or customers; physical attacks

## Things we already know and have published

Reporting one of these is still welcome — it tells us it matters to you — but it is not a new
finding. Each is stated with its evidence in `FAILURE_MODES.md`, `IEC62443_MAPPING.md` and
`DILIGENCE_QA.md`:

- **No penetration test has ever been performed.** Declared gap (IEC 62443-4-1 SVV-4).
- **`foundrynet.io` publishes DMARC at `p=none`** and the apex SPF ends `~all`, so a spoofed
  message is reported but not rejected. Verified by DNS lookup 2026-10-08.
- **Signing keys are software keys on the filesystem** (`assurance: software_key`). The
  hardware path (PKCS#11 / TPM2 / secure element) is specified and not implemented.
- **Corpus-release and site-config signatures are symmetric HMAC**, and three HMAC keys
  default to a non-secret "not-for-production" string in source with nothing refusing the
  default.
- **Truncation from the end of an audit chain is not detected.** Deletion, reordering and
  insertion in the middle are. Externally anchored checkpoints are designed, not enabled.
- **Unauthenticated fieldbus protocols carry no wire authenticity** and Forge cannot add any.
  Measured, not assumed — see `SAFETY_SCOPE.md` §4.
- **Production runs a single replica** with in-process rate limiters; a redeploy resets a
  limiter window.
- **No vulnerability scanner runs against the published kernel image in CI.**

## Not a safety channel

This is a **security** contact. Forge is **not a safety-rated function**: no SIL claim
(IEC 61508 / IEC 62061), no PL or Category claim (ISO 13849), no notified-body assessment. It
does not replace safety PLCs, emergency-stop circuits, guard-door interlocks or robot safety
controllers, and a guardrail verdict binds only where it is actually enforced. If you have a
concern about a machine's physical safety, that is your plant's safety system and your
integrator, not this mailbox. Product safety scope: `SAFETY_SCOPE.md`.

## Cryptography

If you need to encrypt a report, say so in a first plain-text mail and we will agree a method.
Foundry Labs does not currently publish a PGP key, and will not publish one it cannot commit
to monitoring.

---

**Contact:** foundrynet@proton.me
*Foundry Labs LLC · Forge by Foundry Labs*
