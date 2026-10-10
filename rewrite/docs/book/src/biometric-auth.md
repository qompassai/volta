# Biometric authentication

Operator power is passkey power. Volta uses WebAuthn/FIDO2 with
platform authenticators — the fingerprint (or face, or PIN) that
unlocks *your* passkey on *your* device.

<details>
<summary>The one fact to keep straight</summary>

**Biometric data never leaves the authenticator.** User
verification happens inside the device; volta receives a
signature and stores only the credential **public key**,
credential id, and signature counter. There is no API field for
a fingerprint, no template store, no biometric database — the
protocol has no such message, and volta adds none.

</details>

<details>
<summary>The ceremonies</summary>

Registration and authentication follow the standard two-call
shape (`.../webauthn/register/options|verify`,
`.../webauthn/auth/options|verify`). Every ceremony demands
`userVerification: "required"` — an assertion without the UV
flag is rejected even when its signature verifies. Challenges
are 32 random bytes, single-use, 300 s. The credential algorithm
allowlist is exactly COSE −8 and −7; anything else fails
registration. The first operator enrolls with a one-time
bootstrap token (printed by the server console or
`voltactl operator bootstrap`, stored only as a hash).

</details>

<details>
<summary>Sessions, step-up, clones</summary>

A successful assertion mints a 900 s opaque session
(`HttpOnly; Secure; SameSite=Strict` cookie or Bearer). The
irreversible actions — total deletion, unpublishing, server
custody decapsulation — additionally require a **step-up**: an
assertion completed within the last 300 s. A signature counter
that fails to increase locks the credential and returns
`E_WEBAUTHN_CLONE_DETECTED` (counter-less authenticators are
accepted per the WebAuthn specification and recorded as such).

</details>

<details>
<summary>No fallback, on purpose</summary>

There is no password, TOTP, or emailed-code fallback for a lost
passkey (WA-3). Recovery is a second pre-registered passkey, or
the break-glass path: `voltactl operator recover --yes` on the
host wipes all credentials (audited, destructive, local-only) so
enrollment can begin again. This is stated to operators at
enrollment, not discovered at lockout.

</details>
