// The Tailscale-only hardened build. Features whose job is to reach the
// internet from the device (online updates, PicoClaw, remote image downloads,
// Wi-Fi, mDNS) are hidden here and their routes are not registered on the
// server; see server/hardened/hardened.go.
export const HARDENED = true;
