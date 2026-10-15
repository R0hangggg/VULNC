# Postbox

A small local correspondence application written in C. Messages stay on this computer; the application does not connect to an email provider.

## Build

Requires a C11 compiler, Make, and OpenSSL 3 development headers and library. On Debian or Ubuntu, the packages are `build-essential` and `libssl-dev`.

Build with `make` in the project directory.

## Use

```sh
./postbox init
./postbox send maya@fieldwork.example 'Thursday coffee' 'Thursday morning works. See you at the studio!'
./postbox list
./postbox read <reference-shown-by-list>
```

`init` creates a private local workspace and refuses to overwrite an existing one. `send` seals a message for the local recipient identity and records an authenticated local receipt. `list` checks the stored envelopes before listing them. `read` checks and opens a message.

Recipient addresses are labels, not remote destinations. This first version models sender, recipient, and relay identities in one local workspace. Only use sample correspondence: identity files are unencrypted and this version has no account or passphrase management.

The binary envelope is a local native C representation, not a portable network format. Keep the same build architecture when reading existing messages. The repository archive contains source only, no generated identities or correspondence.
