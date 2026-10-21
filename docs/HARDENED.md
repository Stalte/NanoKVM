# Hardened build: Tailscale-only NanoKVM

This fork builds a NanoKVM application package that cannot reach the internet
except through Tailscale. It installs through the stock **Settings › Update ›
Offline update** page, so the SD card does not have to be rebuilt.

It targets the SG2002 devices (NanoKVM Cube and NanoKVM-PCIe). It was written
against application 2.4.3 on image v1.3.0 and later.

## What changes on the device

| Area | Stock | Hardened |
|---|---|---|
| Outbound internet | Any process | Only the `tailscale` user (uid 4164). Everything else is dropped by the firewall, IPv4 and IPv6 |
| Inbound | Anything listening | Web UI and SSH from `LAN_SUBNETS` over Ethernet, the tailnet (via `tailscale serve`), and loopback |
| Firewall | A few per-port rules | Default deny on INPUT, OUTPUT and FORWARD, loaded at boot by `S02hardening` before the network starts |
| Online updates | `cdn.sipeed.com`, preview channel, custom servers | Removed. Offline updates only, and they must be signed with your key |
| PicoClaw (AI agent) | Downloads a runtime, calls cloud LLMs | Removed from the package, the server and the UI |
| Remote image download | Server fetches any URL | Removed. Upload images from the browser |
| Tailscale | Downloaded from `pkgs.tailscale.com`, runs as root | Pinned 1.104.2 in the package (checksum verified at build), runs unprivileged in userspace-networking mode, log upload off |
| mDNS, SSDP, dnsmasq | Available | Stopped and removed |
| Wi-Fi | Available | Init script replaced with a stub that keeps `wlan0` down |
| Time | NTP | NTP removed. The clock is set from the certificate-checked `Date` header of `controlplane.tailscale.com`, fetched as the `tailscale` user |
| DNS | Vendor list includes 114.114.114.114, 119.29.29.29, 223.5.5.5 | `DNS_SERVERS` (default 1.1.1.1, 9.9.9.9), usable by tailscaled only |
| SSH | Root password login | Key only (`/boot/authorized_keys`), no forwarding |
| Audio capture | `/dev/snd` readable | `/dev/snd/*` set to mode 000 |

Everything else (video, keyboard, mouse, virtual media, terminal, scripts,
Wake-on-LAN, ATX power, users) works as before.

## One-time setup

### 1. Make your update signing key

Do this on your own computer. The private key never leaves it. With Go
installed:

```sh
cd server
go run ./cmd/nanokvm-sign keygen -out ~/.nanokvm/update
cp ~/.nanokvm/update.pub pkgsign/keys/owner.pub
git add pkgsign/keys/owner.pub && git commit -m "Add update signing key"
```

You can also download a prebuilt `nanokvm-sign` for your platform from the
`nanokvm-sign-*` artifact of the **NanoKVM Package** workflow.

Back up `~/.nanokvm/update.key`. If you lose it, the devices will refuse every
future update until you reflash their SD cards.

### 2. Build the package

The **NanoKVM Package** workflow builds on every pull request and on manual
dispatch:

1. Run the **Builder Image** workflow once, so that
   `ghcr.io/<you>/nanokvm-builder` exists.
2. Run **NanoKVM Package** with a version such as `2.5.901`.
3. Download the artifact. It contains `nanokvm_<version>.tar.gz`,
   `sha256.txt`, `BUILD_INFO.txt` and `AUDIT.txt`. `AUDIT.txt` lists every
   check the package passed and every endpoint string found in the shipped
   binaries.

A release build fails if `server/pkgsign/keys/` has no key. Pull request
builds are allowed to skip it and print a warning. Never install an unkeyed
build on a device you keep: it would accept unsigned updates.

### 3. Sign it

```sh
nanokvm-sign sign -key ~/.nanokvm/update.key nanokvm_2.5.901.tar.gz
# -> signed/nanokvm_2.5.901.tar.gz and its sha256
```

The signature is stored inside the archive, so the device's upload page takes
it unchanged. Signing is needed from the second hardened install onwards. The
first install runs on stock firmware, which does not check signatures, but
signing it anyway does no harm.

### 4. Prepare each device

1. **Reflash** the SD card with the official image, and check the image's
   checksum against Sipeed's release page. An application update cannot clean
   an operating system that is already compromised.
2. To use SSH, put your public key on the SD card's boot partition as
   `authorized_keys`. Password logins are disabled.
3. If your LAN is not `192.168.10.0/24`, put a `hardening.conf` on the boot
   partition with your subnet, for example `LAN_SUBNETS="10.0.5.0/24"`.

### 5. Install

1. Boot the device, open its web UI on the LAN, and set the admin password.
2. Go to **Settings › Update › Offline update**, paste the sha256, and upload
   the package.
3. The device restarts its services. **Reboot it once** afterwards, so the
   firewall loads before the network on a clean boot.
4. Go to **Settings › Tailscale** and log in. The device shows a login URL; open
   it on your computer.
5. Once Tailscale reports **Running**, the device closes its LAN-wide setup
   window by itself. From then on only `LAN_SUBNETS` and the tailnet can reach
   it.

Until the first Tailscale login, the web UI and SSH answer any address on the
Ethernet port, so a wrong `LAN_SUBNETS` cannot lock a fresh install out.

### 6. Tailnet policy

Lock the device down on the Tailscale side too: tag it and let only your own
devices reach it. In the Tailscale admin console, under **Access controls**:

```json
{
  "tagOwners": { "tag:kvm": ["autogroup:admin"] },
  "grants": [
    { "src": ["autogroup:member"], "dst": ["tag:kvm"], "ip": ["tcp:80", "tcp:443", "tcp:22"] }
  ]
}
```

Then disable key expiry for the device, so it does not drop off the tailnet
after 180 days.

## Day to day

* **Check the state:** `ssh root@<device> /kvmapp/hardening/harden.sh status`
  prints `mode=locked egress=owner …`. `egress=ports` means the kernel lacks
  the owner match and egress is limited by port only. `egress=none` means no
  firewall could be loaded.
* **See what was dropped:** `dmesg | grep nkvm-out-drop` shows outbound
  packets the firewall refused, rate limited to 6 per minute.
* **Recovery:** if Tailscale breaks and you are not on `LAN_SUBNETS`, create an
  empty file named `kvm-recovery` on the SD card's boot partition. The next boot
  opens the web UI and SSH to any Ethernet address, for that boot only.
* **Updating Tailscale:** change `scripts/tailscale.lock` (version and
  sha256), build, sign, and upload.

## Verify it yourself

Run a packet capture for 24 hours on the switch port or a mirror port, from a
fresh boot:

```sh
tcpdump -i <iface> -w nanokvm-24h.pcap host <device-ip>
```

Expected traffic:

* DHCP with your router.
* UDP 41641 and 3478, and TCP 443, to Tailscale's control server, DERP relays
  and your other nodes. All of it comes from the `tailscale` user.
* DNS to `DNS_SERVERS`, for Tailscale names only.
* Your own sessions to ports 80, 443 and 22 from `LAN_SUBNETS`.

Anything else is a finding. Look it up in `dmesg | grep nkvm-out-drop` on the
device as well.

## Files

| Path | Role |
|---|---|
| `kvmapp/hardening/harden.sh` | Firewall, service lockdown, SSH, DNS, Tailscale setup, keeper loop |
| `kvmapp/hardening/hardening.conf` | Defaults. Overridden by `/etc/kvm/hardening.conf`, then `/boot/hardening.conf` |
| `kvmapp/system/init.d/S02hardening` | Loads the firewall before `S30eth` |
| `kvmapp/system/init.d/S98tailscaled` | Unprivileged, userspace tailscaled |
| `kvmapp/system/init.d/S30wifi` | Stub that keeps Wi-Fi down |
| `server/cmd/nanokvm-guard` | Static helper: drop privileges, time sync |
| `server/cmd/nanokvm-sign` | Key generation, signing, verification |
| `server/pkgsign` | Package manifest, signature checks, trusted keys |
| `server/hardened` | Build flag the server checks to leave internet-facing features out |
| `scripts/fetch-tailscale.sh`, `scripts/tailscale.lock` | Pinned Tailscale download |
| `scripts/audit-package.sh` | Structural audit of a built package |
| `.github/workflows/security.yml` | govulncheck, gosec, pnpm audit, secret scan |

## Limits

* **The OS image is still Sipeed's.** The kernel, BusyBox, OpenSSH and the
  vendor kernel modules come from the stock SD image. A kernel-level implant
  could bypass netfilter. Reflashing a checksum-verified image and the 24-hour
  capture are how you get confidence about it.
* **Closed vendor libraries.** `server/dl_lib/*.so` (camera, ISP, codecs) have
  no source. A strings scan finds no network endpoints in them. They run inside
  `NanoKVM-Server` as root, and the firewall refuses root's outbound traffic.
* **Admins are root.** The web terminal and script runner give an admin a root
  shell by design. Use a strong password, and give everyday users the `user`
  role.
* **Web login over plain HTTP.** The browser encrypts the password with a key
  hardcoded in the web UI, which is obfuscation, not protection. Over Tailscale
  the link is encrypted anyway. On the LAN, turn on HTTPS under
  **Settings › Network › TLS**.
