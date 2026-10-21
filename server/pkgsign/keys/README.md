# Trusted update signing keys

Every `*.pub` file in this directory is compiled into `NanoKVM-Server`, and the
hardened build installs an offline update only when its signature verifies
against one of them.

Generate a key pair on your own machine, keep the private key there, and commit
only the public half:

```sh
cd server
go run ./cmd/nanokvm-sign keygen -out ~/.nanokvm/update
cp ~/.nanokvm/update.pub pkgsign/keys/owner.pub
```

With no `*.pub` file here the build still works, but it accepts unsigned
offline updates, and release builds refuse to package it. See
`docs/HARDENED.md`.
