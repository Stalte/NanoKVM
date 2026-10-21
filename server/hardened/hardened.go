// Package hardened marks this build as the Tailscale-only hardened variant.
//
// The hardened build keeps every feature that works on the local network and
// over Tailscale, and removes every feature whose job is to reach the internet
// on its own: the online updater, PicoClaw, remote image downloads, the
// Tailscale downloader, mDNS and Wi-Fi. The firewall installed by
// kvmapp/hardening/harden.sh enforces the same rule at the network layer, so
// this flag only keeps the server from offering what the firewall would refuse.
package hardened

const Enabled = true

// HardeningScript applies the firewall and the service lockdown. It is
// idempotent and safe to run on every start.
const HardeningScript = "/kvmapp/hardening/harden.sh"
