#!/bin/sh
#
# NanoKVM hardened build: Tailscale-only network lockdown.
#
#   harden.sh boot      early boot (S02hardening): consume the recovery switch,
#                       apply sysctls and the firewall before any interface is up
#   harden.sh apply     full, idempotent lockdown: services, users, Tailscale,
#                       SSH, DNS, firewall, background keeper
#   harden.sh firewall  rebuild the firewall only
#   harden.sh status    print the current mode
#
# The policy: nothing on this device may open a connection to the internet
# except tailscaled, which runs as its own unprivileged user. The web UI and
# SSH answer on the loopback interface (reached through "tailscale serve") and
# from the LAN subnets in hardening.conf. Everything else is dropped, in and
# out, on every interface, for IPv4 and IPv6.

HARDEN_DIR="${HARDEN_DIR:-/kvmapp/hardening}"
GUARD="$HARDEN_DIR/nanokvm-guard"
STATE_DIR="${STATE_DIR:-/etc/kvm}"
RUN_DIR="${RUN_DIR:-/var/run}"
LOCKED_FLAG="$STATE_DIR/hardening.locked"
RECOVERY_SWITCH=/boot/kvm-recovery
RECOVERY_FLAG="$RUN_DIR/nkvm-recovery"
STATUS_FILE="$RUN_DIR/nkvm-hardening.status"
KEEPER_PID="$RUN_DIR/nkvm-keeper.pid"
LOG_TAG=nkvm-harden

. "$HARDEN_DIR/hardening.conf"
[ -f "$STATE_DIR/hardening.conf" ] && . "$STATE_DIR/hardening.conf"
[ -f /boot/hardening.conf ] && . /boot/hardening.conf

log() {
    echo "$LOG_TAG: $*"
    logger -t "$LOG_TAG" "$*" 2>/dev/null || true
}

have() {
    command -v "$1" >/dev/null 2>&1
}

# --- mode --------------------------------------------------------------------

ts_running() {
    have tailscale || return 1
    tailscale status --json 2>/dev/null | grep -q '"BackendState": *"Running"'
}

# open:    the web UI and SSH answer on eth0 from any address. True for the one
#          boot after the recovery switch, and until the device has logged in
#          to Tailscale for the first time (so a wrong LAN_SUBNETS cannot lock
#          a fresh install out).
# locked:  LAN_SUBNETS and the tailnet only.
mode() {
    if [ -e "$RECOVERY_FLAG" ]; then
        echo recovery
    elif [ ! -e "$LOCKED_FLAG" ]; then
        echo pending
    else
        echo locked
    fi
}

# --- firewall ----------------------------------------------------------------

# Probe a match or target by loading it into a scratch chain.
ipt_supports() {
    iptables -N NKVM_PROBE 2>/dev/null || iptables -F NKVM_PROBE
    iptables -A NKVM_PROBE "$@" >/dev/null 2>&1
    rc=$?
    iptables -F NKVM_PROBE 2>/dev/null
    iptables -X NKVM_PROBE 2>/dev/null
    return $rc
}

# The rule set, one iptables-restore line each. It is applied in one
# transaction where iptables-restore exists, so there is never a moment with
# half a firewall.
ipv4_rules() {
    m="$1"
    echo "*filter"
    echo ":INPUT DROP [0:0]"
    echo ":FORWARD DROP [0:0]"
    echo ":OUTPUT DROP [0:0]"

    # Inbound
    echo "-A INPUT -i lo -j ACCEPT"
    echo "-A INPUT -m state --state INVALID -j DROP"
    echo "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
    echo "-A INPUT -i eth0 -p udp --sport 67 --dport 68 -j ACCEPT"
    echo "-A INPUT -i eth0 -p udp --dport $TS_PORT -j ACCEPT"
    for net in $LAN_SUBNETS; do
        for port in $SERVICE_PORTS; do
            echo "-A INPUT -i eth0 -s $net -p tcp --dport $port -j ACCEPT"
        done
        echo "-A INPUT -i eth0 -s $net -p icmp --icmp-type echo-request -j ACCEPT"
    done
    if [ "$m" != locked ]; then
        for port in $SERVICE_PORTS; do
            echo "-A INPUT -i eth0 -p tcp --dport $port -j ACCEPT"
        done
    fi
    [ "$CAN_LOG" = 1 ] && echo "-A INPUT -m limit --limit 6/min -j LOG --log-prefix \"nkvm-in-drop: \""

    # Outbound
    echo "-A OUTPUT -o lo -j ACCEPT"
    echo "-A OUTPUT -m state --state INVALID -j DROP"
    echo "-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
    echo "-A OUTPUT -o eth0 -p udp --sport 68 --dport 67 -j ACCEPT"
    if [ "$EGRESS" = owner ]; then
        echo "-A OUTPUT -m owner --uid-owner $TS_UID -j ACCEPT"
    else
        # Fallback for a kernel without the owner match: Tailscale's ports
        # only, for every process. Weaker, and reported as such.
        for port in $TS_PORT 3478 53; do
            echo "-A OUTPUT -p udp --dport $port -j ACCEPT"
        done
        for port in 443 80 53; do
            echo "-A OUTPUT -p tcp --dport $port -j ACCEPT"
        done
    fi
    [ "$CAN_LOG" = 1 ] && echo "-A OUTPUT -m limit --limit 6/min -j LOG --log-prefix \"nkvm-out-drop: \""
    echo "COMMIT"
}

ipv6_rules() {
    echo "*filter"
    echo ":INPUT DROP [0:0]"
    echo ":FORWARD DROP [0:0]"
    echo ":OUTPUT DROP [0:0]"
    echo "-A INPUT -i lo -j ACCEPT"
    echo "-A OUTPUT -o lo -j ACCEPT"
    echo "COMMIT"
}

# Without iptables-restore, replay the same lines one command at a time.
replay() {
    cmd="$1"
    $cmd -P INPUT DROP
    $cmd -P FORWARD DROP
    $cmd -P OUTPUT DROP
    $cmd -F
    $cmd -X 2>/dev/null
    while IFS= read -r line; do
        case "$line" in
            -A*) eval "$cmd $line" || return 1 ;;
        esac
    done
}

firewall() {
    if ! have iptables; then
        log "ERROR: iptables not found, the device is NOT firewalled"
        EGRESS=none
        write_status
        return 1
    fi

    if ipt_supports -m owner --uid-owner "$TS_UID" -j RETURN; then
        EGRESS=owner
    else
        EGRESS=ports
        log "WARNING: kernel has no owner match; egress limited by port, not by process"
    fi
    CAN_LOG=0
    ipt_supports -m limit --limit 6/min -j LOG --log-prefix probe && CAN_LOG=1

    m=$(mode)
    if have iptables-restore && ipv4_rules "$m" | iptables-restore; then
        :
    elif ipv4_rules "$m" | replay iptables; then
        :
    else
        log "ERROR: could not load the IPv4 firewall"
        return 1
    fi

    if have ip6tables; then
        if have ip6tables-restore; then
            ipv6_rules | ip6tables-restore || ipv6_rules | replay ip6tables
        else
            ipv6_rules | replay ip6tables
        fi
    fi

    log "firewall loaded: mode=$m egress=$EGRESS lan=\"$LAN_SUBNETS\""
    write_status
}

sysctls() {
    for kv in \
        net.ipv4.ip_forward=0 \
        net.ipv4.conf.all.rp_filter=1 \
        net.ipv4.conf.all.accept_redirects=0 \
        net.ipv4.conf.all.send_redirects=0 \
        net.ipv4.conf.all.accept_source_route=0 \
        net.ipv4.icmp_echo_ignore_broadcasts=1 \
        net.ipv4.tcp_syncookies=1 \
        net.ipv6.conf.all.disable_ipv6=1 \
        net.ipv6.conf.default.disable_ipv6=1; do
        sysctl -w "$kv" >/dev/null 2>&1
    done
}

# --- services ----------------------------------------------------------------

# Init scripts whose only job is to talk to the network on the device's own
# initiative, or to announce it.
REMOVED_SERVICES="S50avahi-daemon S50ssdpd S80dnsmasq S96picoclaw"
REMOVED_DAEMONS="avahi-daemon ssdpd dnsmasq picoclaw ntpd chronyd wpa_supplicant hostapd udhcpd"

disable_services() {
    for s in $REMOVED_SERVICES; do
        if [ -e "/etc/init.d/$s" ]; then
            "/etc/init.d/$s" stop >/dev/null 2>&1
            rm -f "/etc/init.d/$s"
            log "removed /etc/init.d/$s"
        fi
    done
    for s in /etc/init.d/S*ntp* /etc/init.d/S*chrony*; do
        [ -e "$s" ] || continue
        "$s" stop >/dev/null 2>&1
        rm -f "$s"
        log "removed $s"
    done
    for d in $REMOVED_DAEMONS; do
        killall "$d" >/dev/null 2>&1
    done

    # Wi-Fi: the init script in this package is a stub that keeps the radio
    # down; make sure the running system agrees.
    cp -f /kvmapp/system/init.d/S30wifi /etc/init.d/S30wifi 2>/dev/null
    ip link set wlan0 down >/dev/null 2>&1
    rm -f /etc/kvm/wifi.ssid /etc/kvm/wifi.pass /boot/wifi.ssid /boot/wifi.pass

    # The stock online updater script.
    rm -f /etc/kvm/update-nanokvm.py

    # Audio capture: nothing in the application uses it.
    if [ -d /dev/snd ]; then
        chmod 000 /dev/snd/* 2>/dev/null
    fi
}

# Our boot hooks must be the ones /etc/init.d runs, whatever image this
# package was installed on.
install_init_scripts() {
    for s in S02hardening S95nanokvm; do
        install_if_changed "/kvmapp/system/init.d/$s" "/etc/init.d/$s" 755
    done
}

# --- tailscale ---------------------------------------------------------------

ensure_ts_user() {
    if ! grep -q "^$TS_USER:" /etc/group; then
        echo "$TS_USER:x:$TS_UID:" >> /etc/group
    fi
    if ! grep -q "^$TS_USER:" /etc/passwd; then
        echo "$TS_USER:x:$TS_UID:$TS_UID:tailscale:/var/lib/tailscale:/bin/false" >> /etc/passwd
    fi
    if [ -f /etc/shadow ] && ! grep -q "^$TS_USER:" /etc/shadow; then
        echo "$TS_USER:!:19000:0:99999:7:::" >> /etc/shadow
    fi
    mkdir -p /var/lib/tailscale /var/run/tailscale
    chown -R "$TS_UID:$TS_UID" /var/lib/tailscale /var/run/tailscale
    chmod 700 /var/lib/tailscale
    chmod 755 /var/run/tailscale
}

install_if_changed() {
    src="$1"
    dst="$2"
    perm="$3"
    [ -f "$src" ] || return 1
    if ! cmp -s "$src" "$dst" 2>/dev/null; then
        cp -f "$src" "$dst.nkvm" && chmod "$perm" "$dst.nkvm" && mv -f "$dst.nkvm" "$dst"
        log "installed $dst"
        return 0
    fi
    chmod "$perm" "$dst"
    return 1
}

ensure_tailscale() {
    ensure_ts_user
    changed=0
    install_if_changed "$HARDEN_DIR/../tailscale/tailscaled" /usr/sbin/tailscaled 755 && changed=1
    install_if_changed "$HARDEN_DIR/../tailscale/tailscale" /usr/bin/tailscale 755 && changed=1
    install_if_changed /kvmapp/system/init.d/S98tailscaled /etc/init.d/S98tailscaled 755 && changed=1

    # A tailscaled left running as root by the stock image, or an old binary,
    # has to be replaced by the unprivileged one.
    pid=$(pidof tailscaled 2>/dev/null)
    if [ -n "$pid" ]; then
        uid=$(awk '/^Uid:/ {print $2}' "/proc/${pid%% *}/status" 2>/dev/null)
        if [ "$uid" != "$TS_UID" ] || [ "$changed" = 1 ]; then
            log "restarting tailscaled as $TS_USER"
            /etc/init.d/S98tailscaled restart >/dev/null 2>&1 &
        fi
    else
        /etc/init.d/S98tailscaled start >/dev/null 2>&1 &
    fi
}

# Publish the local services on the tailnet. tailscaled runs in userspace
# networking mode, so this is the only way tailnet traffic reaches them.
ts_serve() {
    ts_running || return 1
    for port in $SERVICE_PORTS; do
        tailscale serve --bg --tcp="$port" "tcp://127.0.0.1:$port" >/dev/null 2>&1 \
            || log "tailscale serve on port $port failed"
    done
    return 0
}

# --- ssh ---------------------------------------------------------------------

SSHD_OPTIONS="PasswordAuthentication=no KbdInteractiveAuthentication=no ChallengeResponseAuthentication=no PermitEmptyPasswords=no PermitRootLogin=prohibit-password X11Forwarding=no AllowTcpForwarding=no AllowAgentForwarding=no GatewayPorts=no PermitTunnel=no"

sshd_render() {
    cfg="$1"
    options="$2"
    echo "# --- NanoKVM hardened build (harden.sh) ---"
    for kv in $options; do
        echo "${kv%%=*} ${kv#*=}"
    done
    echo "# --- end ---"
    pattern=$(for kv in $options; do printf '%s|' "${kv%%=*}"; done)
    pattern="${pattern%|}"
    sed -e '/^# --- NanoKVM hardened build/,/^# --- end ---/d' "$cfg" \
        | grep -Ev "^[[:space:]]*#?[[:space:]]*($pattern)[[:space:]]"
}

harden_ssh() {
    cfg=/etc/ssh/sshd_config
    [ -f "$cfg" ] || return 0

    # Our options go first: sshd takes the first value it reads, and anything
    # appended would land inside a trailing Match block. An option this
    # OpenSSH does not know would stop sshd from starting, so test the result
    # and drop whatever it rejects.
    tmp="$cfg.nkvm"
    options="$SSHD_OPTIONS"
    tries=0
    while :; do
        sshd_render "$cfg" "$options" > "$tmp"
        err=$(/usr/sbin/sshd -t -f "$tmp" 2>&1) && break
        bad=$(echo "$err" | sed -n 's/.*[Bb]ad configuration option: *\([A-Za-z]*\).*/\1/p' | head -n1)
        tries=$((tries + 1))
        if [ -z "$bad" ] || [ "$tries" -gt 5 ]; then
            log "sshd: cannot harden config ($err); left unchanged"
            rm -f "$tmp"
            return 1
        fi
        options=$(for kv in $options; do [ "${kv%%=*}" = "$bad" ] || printf '%s ' "$kv"; done)
    done
    if ! cmp -s "$tmp" "$cfg"; then
        mv -f "$tmp" "$cfg"
        killall -HUP sshd >/dev/null 2>&1
        log "sshd: password logins disabled"
    else
        rm -f "$tmp"
    fi

    # Keys come from the SD card, so a key can be added without a password.
    if [ -f /boot/authorized_keys ]; then
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
        if ! cmp -s /boot/authorized_keys /root/.ssh/authorized_keys; then
            cp -f /boot/authorized_keys /root/.ssh/authorized_keys
            log "sshd: installed /boot/authorized_keys"
        fi
        chmod 600 /root/.ssh/authorized_keys
    fi
}

# --- dns ---------------------------------------------------------------------

set_dns() {
    [ -n "$DNS_SERVERS" ] || return 0
    tmp=/etc/resolv.conf.nkvm
    for s in $DNS_SERVERS; do
        echo "nameserver $s"
    done > "$tmp"
    if ! cmp -s "$tmp" /etc/resolv.conf 2>/dev/null; then
        rm -f /etc/resolv.conf
        mv -f "$tmp" /etc/resolv.conf
    else
        rm -f "$tmp"
    fi
}

# --- keeper ------------------------------------------------------------------

# One background loop: keeps the clock right, publishes the services on the
# tailnet, and closes the "pending" window once Tailscale is logged in.
keeper() {
    synced=0
    last_sync=0
    while :; do
        now=$(date +%s)
        if [ "$synced" = 0 ] || [ $((now - last_sync)) -ge 21600 ]; then
            if "$GUARD" timesync -as "$TS_USER" -url "$TIMESYNC_URL"; then
                synced=1
                last_sync=$(date +%s)
            fi
        fi
        if ts_running; then
            if [ ! -e "$LOCKED_FLAG" ]; then
                touch "$LOCKED_FLAG"
                log "Tailscale is logged in; closing the LAN-wide setup window"
                firewall
            fi
            [ -e "$RUN_DIR/nkvm-served" ] || { ts_serve && touch "$RUN_DIR/nkvm-served"; }
        else
            rm -f "$RUN_DIR/nkvm-served"
        fi
        write_status
        if [ "$synced" = 1 ]; then sleep 60; else sleep 15; fi
    done
}

start_keeper() {
    if [ -f "$KEEPER_PID" ] && kill -0 "$(cat "$KEEPER_PID")" 2>/dev/null; then
        return 0
    fi
    # Detach completely: the server waits for this script's output, and a
    # child holding the pipe open would make it wait forever.
    ( keeper ) </dev/null >/dev/null 2>&1 &
    echo $! > "$KEEPER_PID"
}

# --- status ------------------------------------------------------------------

write_status() {
    keys=0
    [ -f /root/.ssh/authorized_keys ] && keys=$(grep -c '^[^#]' /root/.ssh/authorized_keys)
    ts=stopped
    ts_running && ts=running
    {
        echo "mode=$(mode)"
        echo "egress=${EGRESS:-unknown}"
        echo "lan_subnets=$LAN_SUBNETS"
        echo "tailscale=$ts"
        echo "ssh_keys=$keys"
    } > "$STATUS_FILE.tmp" && mv -f "$STATUS_FILE.tmp" "$STATUS_FILE"
}

# --- entry points ------------------------------------------------------------

case "$1" in
    boot)
        if [ -e "$RECOVERY_SWITCH" ]; then
            rm -f "$RECOVERY_SWITCH"
            touch "$RECOVERY_FLAG"
            log "recovery switch found: web UI and SSH open on eth0 for this boot"
        fi
        sysctls
        firewall
        disable_services
        ;;
    apply)
        sysctls
        firewall
        install_init_scripts
        disable_services
        set_dns
        harden_ssh
        ensure_tailscale
        start_keeper
        ;;
    firewall)
        firewall
        ;;
    serve)
        ts_serve
        ;;
    status)
        [ -f "$STATUS_FILE" ] && cat "$STATUS_FILE" || echo "mode=$(mode)"
        ;;
    *)
        echo "Usage: $0 {boot|apply|firewall|serve|status}"
        exit 1
        ;;
esac
