#!/usr/bin/env bash
# Smoke-test a deployed mqttproxy the way a real client uses it: MQTT over
# wss, with an Identity access token in the CONNECT password.
#
# Usage:
#   scripts/smoke.sh [--host HOST] [--filter TOPIC] [--no-publish]
#
# Checks:
#   1. a valid token connects, subscribes and receives messages
#   2. a malformed token is refused
#   3. a CONNECT with no password is refused
#   4. a publish by a "user"-role token is denied and never reaches the broker
#      (skipped with --no-publish, which makes the run read-only)
#
# Run it before a deploy for a baseline, and again after.
#
# Token: $MQTT_TOKEN if set, otherwise fetched with the sweenet-auth skill's
# auth.py ($SWEENET_AUTH, default below). Check 4 assumes the token's role
# may not publish; with an admin token use --no-publish.
#
# Requires mosquitto_sub/mosquitto_pub 2.x (for --ws), curl and python3.
# Exit: 0 all checks passed, 1 a check failed, 2 a precondition failed.

set -euo pipefail

HOST=mqtt.swee.net
FILTER='#'
PUBLISH=1
SWEENET_AUTH="${SWEENET_AUTH:-$HOME/src/github.com/sweeney/claude/plugins/swee/skills/sweenet-auth/auth.py}"

usage() { sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; }
die()   { echo "smoke: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --host)       HOST="${2:?--host needs a value}"; shift 2 ;;
        --filter)     FILTER="${2:?--filter needs a value}"; shift 2 ;;
        --no-publish) PUBLISH=0; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            usage >&2; die "unknown argument: $1" ;;
    esac
done

for cmd in mosquitto_sub mosquitto_pub curl python3; do
    command -v "$cmd" >/dev/null || die "$cmd not found"
done

if [ -n "${MQTT_TOKEN:-}" ]; then
    TOKEN="$MQTT_TOKEN"
else
    [ -f "$SWEENET_AUTH" ] || die "no MQTT_TOKEN and no auth.py at $SWEENET_AUTH"
    TOKEN=$(python3 "$SWEENET_AUTH" token -q) || die "could not get a token from $SWEENET_AUTH"
fi
# The proxy takes the username from the token's usr claim; send the same.
USR=$(printf '%s' "$TOKEN" | python3 -c '
import base64, json, sys
p = sys.stdin.read().split(".")[1]
print(json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))["usr"])
' 2>/dev/null) || die "token is not a JWT with a usr claim"

WATCH=$(mktemp)
SUBERR=$(mktemp)
trap 'rm -f "$WATCH" "$SUBERR"' EXIT
CONN=(--ws -h "$HOST" -p 443 --tls-use-os-certs -V mqttv311)
pass=0 fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

echo "== health"
curl -s -m 10 "https://$HOST/health" || echo "(no response)"
echo

# mosquitto_sub -W exits 0 when -C messages arrived, 27 when it was connected
# but timed out first, and anything else when it never got a working
# connection. So 0 and 27 both mean the broker accepted the client.
accepted() { [ "$1" -eq 0 ] || [ "$1" -eq 27 ]; }

echo "== 1. valid token: subscribe '$FILTER', expect messages"
# Messages from stdout only: mosquitto_sub's own errors ("Timed out") go to
# stderr and must not count as messages.
out=$(mosquitto_sub "${CONN[@]}" -i "smoke-$$-sub" -u "$USR" -P "$TOKEN" -t "$FILTER" -v -C 5 -W 20 2>"$SUBERR") && rc=0 || rc=$?
n=$(printf '%s\n' "$out" | grep -c ' ' || true)
# A quiet filter may time out (27) after fewer than -C messages; any message
# at all proves the subscription works.
if accepted "$rc" && [ "$n" -ge 1 ]; then
    ok "received $n message(s); topics: $(printf '%s\n' "$out" | awk '{print $1}' | sort -u | head -5 | tr '\n' ' ')"
else
    bad "rc=$rc: $(cat "$SUBERR" - <<<"$out" | head -3)"
fi

echo "== 2. malformed token: expect connection refused"
out=$(mosquitto_sub "${CONN[@]}" -i "smoke-$$-bad" -u "$USR" -P not.a.jwt -t "$FILTER" -C 1 -W 10 2>&1) && rc=0 || rc=$?
if ! accepted "$rc"; then ok "refused (rc=$rc): $(printf '%s' "$out" | head -1)"; else bad "malformed token was accepted (rc=$rc)"; fi

echo "== 3. no password: expect connection refused"
out=$(mosquitto_sub "${CONN[@]}" -i "smoke-$$-nopw" -u "$USR" -t "$FILTER" -C 1 -W 10 2>&1) && rc=0 || rc=$?
if ! accepted "$rc"; then ok "refused (rc=$rc): $(printf '%s' "$out" | head -1)"; else bad "client without a password was accepted (rc=$rc)"; fi

if [ "$PUBLISH" -eq 1 ]; then
    echo "== 4. user-role publish: expect it denied"
    # Watch a throwaway topic with the valid token while publishing to it. A
    # denied publish never reaches the broker, so the watcher must not see it.
    topic="smoke/mqttproxy/$$"
    mosquitto_sub "${CONN[@]}" -i "smoke-$$-watch" -u "$USR" -P "$TOKEN" -t "$topic" -C 1 -W 8 >"$WATCH" 2>&1 &
    wpid=$!
    sleep "${SMOKE_SETTLE:-2}"   # let the watcher subscribe first
    mosquitto_pub "${CONN[@]}" -i "smoke-$$-pub" -u "$USR" -P "$TOKEN" -t "$topic" -m smoke -q 1 >/dev/null 2>&1 && prc=0 || prc=$?
    wait "$wpid" && wrc=0 || wrc=$?
    # Only a watcher that was connected and timed out (27) proves the publish
    # never arrived. One that never connected saw nothing either way.
    if grep -qx smoke "$WATCH"; then
        bad "publish reached the broker on $topic"
    elif [ "$wrc" -eq 27 ]; then
        ok "publish did not reach the broker (pub rc=$prc)"
    else
        bad "inconclusive: the watcher did not stay connected (rc=$wrc): $(head -1 "$WATCH")"
    fi
else
    echo "== 4. skipped (--no-publish)"
fi

echo "== result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
