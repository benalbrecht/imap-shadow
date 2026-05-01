# imap-shadow

A small transparent IMAP proxy that sits in front of an IMAP server (built
for Stalwart, but server-agnostic) and hides specific shared folders from
specific users.

It exists to work around the lack of *deny* / negative ACLs in IMAP
servers whose ACL model is strictly additive: if a user inherits access to
a shared mailbox via group membership, there is no way to suppress just
one folder for them. imap-shadow is a UI/UX workaround that drops the
matching `LIST` / `LSUB` / `STATUS` lines on their way back to the
client.

## Scope — UI/UX only, not authorization

imap-shadow is not an access-control system. Hidden folders are expected
to be empty and non-confidential; the goal is purely to declutter
clients. A user who types the exact mailbox name in `SELECT`, `EXAMINE`,
or `STATUS` is **allowed through unchanged**. True access control belongs
in the IMAP server's ACL layer.

## What it does

- Terminates TLS on `:993` using its own ACME-managed certificate
  (HTTP-01 challenge on `:80`).
- Forwards every byte to the upstream IMAP server verbatim, except:
  - rewrites `CAPABILITY` to strip mechanisms it can't safely transit
    (`COMPRESS=DEFLATE`, `REFERRAL`, channel-binding SASL mechanisms);
  - snoops the authenticated username during `LOGIN` and `AUTHENTICATE
    PLAIN | XOAUTH2 | OAUTHBEARER`;
  - drops untagged `LIST`, `LSUB`, `STATUS` responses whose mailbox name
    matches the per-user blocklist.
- Decodes mailbox names from modified UTF-7 (the wire form) before
  matching, so config rules can be written in plain UTF-8.
- Hot-reloads rules on `SIGHUP`.

## Configuration

See [config.toml](./config.toml) for a fully-commented sample.

Rule semantics:

| Field           | Purpose                                                                     |
| --------------- | --------------------------------------------------------------------------- |
| `user`          | Authenticated username; `"*"` matches everyone.                             |
| `hide`          | Mailbox names to hide. Each entry hides that mailbox **and all subfolders**. |
| `hide_personal` | If true, hide every top-level folder in the user's own account except `INBOX`. Does not affect the shared namespace. |

`INBOX` is hardcoded to never be hidden.

When several rules match the same user, all `hide` lists are unioned and
`hide_personal` is OR-ed. Rule order is irrelevant.

## Build

```sh
go build -o imap-shadow ./cmd/imap-shadow
```

## Run

```sh
sudo install -m 0755 imap-shadow /usr/local/bin/
sudo install -d -m 0755 /etc/imap-shadow
sudo install -m 0600 config.toml /etc/imap-shadow/config.toml
sudo install -m 0644 systemd/imap-shadow.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now imap-shadow
```

## Constraints

- HTTP-01 is the only supported ACME challenge type. The `acme.hostnames`
  must resolve to this host and `:80` must be reachable from the public
  internet for issuance and renewal.
- Terminating TLS at the proxy breaks `tls-server-end-point` channel
  binding, so SCRAM-`*`-PLUS and other channel-binding-required SASL
  mechanisms must be stripped from advertised capabilities.
- `COMPRESS=DEFLATE` must be stripped — otherwise the proxy would have to
  inflate/deflate every frame to do its filtering.
- `REFERRAL` must be stripped — otherwise a referred client could
  reconnect directly to the backend and bypass the proxy.

## Tests

```sh
go test ./...
```

The tree is largely pure-function and unit-tested; integration tests use
in-memory `net.Pipe` pairs.
