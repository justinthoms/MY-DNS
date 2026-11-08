# How licensing works, and its limits

## Signed documents

The vendor's license server (License Manager, a separate product) signs every license and every status answer with
**Ed25519**. ISP NetControl verifies them with public keys built into the
binary (`set-trusted-keys.sh`). The signature covers the document type, the
key ID and the exact payload bytes, so a license cannot be edited, a status
answer cannot be passed off as a license, and the key ID cannot be swapped.
Forged, modified and wrong-key documents are rejected.

A license contains: license ID, serial number, customer, edition, features,
client limit, **hardware ID**, validity period. It is valid only on the server
whose hardware ID it names.

## Hardware ID

A SHA-256 hash of `/etc/machine-id` and, where present, the DMI product UUID
(`/sys/class/dmi/id/product_uuid`). It reveals nothing about the machine. It
changes when the operating system is reinstalled (new machine-id) or the
server is replaced; that is a hardware migration (below).

## Trial

The first start of ISP NetControl begins a **30-day trial with all
features**. The length is fixed in the binary. When the trial ends:

- DNS **keeps answering** (plain forwarding), so subscribers are never cut off.
- Filtering stops; the block/allow lists and query log are not used.
- ISP NetControl's firewall table is removed (the host's own rules stay).
- The DNS filtering, query log and firewall pages show "license required".
  DNS settings, the License page and the audit log keep working.

## Clock and state tampering

ISP NetControl stores the trial start and a **high-water mark** (the latest
time it has ever seen) twice: in the database and in
`/var/lib/isp-netcontrol/license.state`, each with an HMAC keyed by the
installation's secret and the hardware ID.

- Every license and trial check uses **max(system clock, high-water mark)**.
  Setting the clock back therefore never extends a trial or license. A clock
  more than 10 minutes behind the mark is recorded as `clock_rollback`.
- If either copy fails its integrity check (edited, or copied to another
  server), it is recorded as tampering and the trial is treated as **over**:
  tampering can end a trial early, never extend it.
- If one copy is deleted, it is restored from the other.
- Detected events are shown on the dashboard and the License page.

**What cannot be prevented.** Someone with root on the customer's server
controls the machine completely. They can:

- delete *both* copies and the database (a full reinstall). That looks like
  a fresh installation and starts a new trial;
- patch the binary or read the installation secret from `.env`.

These are detected where possible but cannot be fully prevented by any
software running on hardware the customer controls. The protection that
does hold is cryptographic: without your private signing key nobody can
create a valid *license*, only abuse the trial.

## Online activation, offline activation

- **Online:** the server sends the license key, its hardware ID and host name
  to the License Manager, which binds the license to that hardware and
  returns a signed license file.
- **Offline:** the vendor enters the server's hardware ID in the License
  Manager and hands over the resulting `.lic` file. The server never
  contacts the License Manager.

## Status sync, renewal and revocation

When enabled (the default whenever a License Manager URL is configured),
the server asks the License Manager every 6 hours for the license's status.
It sends only the license ID, the hardware ID, its license serial number and
a random **nonce**; the signed answer must echo that nonce, so an old answer
cannot be replayed.

- **Renewal:** the vendor changes the expiry date; the next sync installs
  the new license file.
- **Revocation:** the vendor revokes the license; the next sync records the
  signed revocation and the licensed features stop. It survives restarts and
  re-uploading the old license file. Reinstating it reverses this.

**Limit: revocation is not instant, and not guaranteed for offline servers.**
It takes effect at the server's next status sync (up to 6 hours, or at once
with **Sync now**). A server that never syncs (offline, sync disabled, or
the License Manager blocked by its operator) keeps using its license until
the license's own expiry date. For offline customers, issue licenses with
shorter terms and renew them.

## Hardware migration

A license is bound to one server. To move it:

1. Vendor: **Release from current hardware** on the license page.
2. Customer: activate the same key on the new server (or the vendor makes an
   offline file for the new hardware ID).
3. The old server loses the license at its next status sync.

Activating on a second server without a release is refused with
`hardware_mismatch`.

## Signing-key rotation

**Signing keys → Rotate** creates a new key and retires the old one. The new
public key is **signed by the previous key** (an endorsement), and the chain
of endorsements is delivered with every activation, status answer and
offline license file. A server that trusts any key in the chain therefore
accepts licenses from the newest key without a software update. Retired
keys stay trusted, so licenses issued before the rotation remain valid.

If a private key may have been **stolen**, rotation alone is not enough: an
attacker holding the old key could endorse a key of their own. In that case
ship a new ISP NetControl build whose built-in keys exclude the compromised
one, and reissue the affected licenses.
