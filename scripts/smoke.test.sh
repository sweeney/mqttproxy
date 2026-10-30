#!/usr/bin/env bash
# Tests for scripts/smoke.sh, run against stub mosquitto_sub, mosquitto_pub
# and curl on PATH, so no network or broker is needed.
#
# Usage: scripts/smoke.test.sh

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SMOKE="$HERE/smoke.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
STUBS="$WORK/bin"
mkdir -p "$STUBS"

# A syntactically valid unsigned JWT whose payload carries usr=tester.
payload=$(printf '{"usr":"tester","rol":"user"}' | base64 | tr '+/' '-_' | tr -d '=\n')
GOOD_TOKEN="e30.${payload}.sig"

# Stub behaviour is steered by env vars:
#   FAKE_ACCEPT_BAD=1  the "broker" accepts malformed or missing passwords
#   FAKE_PUB_LEAKS=1   the "proxy" lets a user publish through
#   FAKE_NO_MSGS=1     a valid subscription receives nothing
#   FAKE_FEW_MSGS=1    a valid subscription receives 2 messages, then times out
#   FAKE_ACCEPT_QUIET=1  bad passwords are accepted, but nothing arrives (rc 27)
#   FAKE_WATCH_DOWN=1  the publish watcher cannot connect (rc 1)
#   FAKE_STATE         directory shared by the stubs
cat >"$STUBS/mosquitto_sub" <<'EOF'
#!/usr/bin/env bash
pw="" topic=""
while [ $# -gt 0 ]; do
    case "$1" in
        -P) pw="$2"; shift 2 ;;
        -t) topic="$2"; shift 2 ;;
        *)  shift ;;
    esac
done
if [ -z "$pw" ] || [ "$pw" = "not.a.jwt" ]; then
    [ "${FAKE_ACCEPT_BAD:-0}" = 1 ] && { echo "x/y hello"; exit 0; }
    [ "${FAKE_ACCEPT_QUIET:-0}" = 1 ] && { echo "Timed out" >&2; exit 27; }
    echo "Connection error: Connection Refused: not authorised" >&2; exit 5
fi
case "$topic" in
    smoke/*)
        [ "${FAKE_WATCH_DOWN:-0}" = 1 ] && { echo "Connection error: Connection refused" >&2; exit 1; }
        sleep 0.5
        if [ -f "$FAKE_STATE/published" ]; then echo smoke; exit 0; fi
        echo "Timed out" >&2; exit 27 ;;
esac
[ "${FAKE_NO_MSGS:-0}" = 1 ] && { echo "Timed out" >&2; exit 27; }
[ "${FAKE_FEW_MSGS:-0}" = 1 ] && { echo 'a/1 {"v":1}'; echo 'a/2 {"v":1}'; echo "Timed out" >&2; exit 27; }
for t in a/1 a/2 b/1 b/2 c/1; do echo "$t {\"v\":1}"; done
EOF
cat >"$STUBS/mosquitto_pub" <<'EOF'
#!/usr/bin/env bash
if [ "${FAKE_PUB_LEAKS:-0}" = 1 ]; then touch "$FAKE_STATE/published"; exit 0; fi
exit 2
EOF
cat >"$STUBS/curl" <<'EOF'
#!/usr/bin/env bash
echo '{"status":"ok","version":"test"}'
EOF
chmod +x "$STUBS"/*

pass=0 fail=0
# run NAME WANT_EXIT WANT_REGEX [env assignments...] -- [smoke args...]
run() {
    local name="$1" want="$2" regex="$3"; shift 3
    local envs=() args=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
    [ $# -gt 0 ] && shift
    args=("$@")
    rm -rf "$WORK/state"; mkdir "$WORK/state"
    local out rc
    out=$(env PATH="$STUBS:$PATH" FAKE_STATE="$WORK/state" SMOKE_SETTLE=0.1 \
              MQTT_TOKEN="$GOOD_TOKEN" ${envs[@]+"${envs[@]}"} \
              "$SMOKE" ${args[@]+"${args[@]}"} 2>&1) && rc=0 || rc=$?
    if [ "$rc" -eq "$want" ] && printf '%s' "$out" | grep -qE "$regex"; then
        echo "ok   $name"; pass=$((pass+1))
    else
        echo "FAIL $name (exit $rc, want $want; output must match /$regex/)"
        printf '%s\n' "$out" | sed 's/^/     | /'
        fail=$((fail+1))
    fi
}

run "healthy proxy passes all four checks" 0 'result: 4 passed, 0 failed'
run "reports the topics it received" 0 'topics: a/1 a/2 b/1 b/2 c/1'
run "--no-publish skips the publish check" 0 'result: 3 passed, 0 failed' -- --no-publish
run "no messages on a valid subscription fails" 1 'FAIL  rc=27' FAKE_NO_MSGS=1
run "accepting a malformed token fails" 1 'malformed token was accepted' FAKE_ACCEPT_BAD=1
run "a quiet filter with a few messages passes" 0 'received 2 message' FAKE_FEW_MSGS=1 -- --no-publish
run "a bad token accepted on a quiet filter fails" 1 'malformed token was accepted' FAKE_ACCEPT_QUIET=1 -- --no-publish
run "a missing password accepted on a quiet filter fails" 1 'without a password was accepted' FAKE_ACCEPT_QUIET=1 -- --no-publish
run "a publish check whose watcher never connected is inconclusive" 1 'inconclusive' FAKE_WATCH_DOWN=1
run "a leaked user publish fails" 1 'publish reached the broker' FAKE_PUB_LEAKS=1
run "a non-JWT token is a precondition failure" 2 'not a JWT with a usr claim' MQTT_TOKEN=garbage
run "no token source is a precondition failure" 2 'no MQTT_TOKEN and no auth.py' MQTT_TOKEN= SWEENET_AUTH=/nonexistent
run "unknown argument is rejected" 2 'unknown argument: --bogus' -- --bogus
run "--help prints usage" 0 'Usage:' -- --help

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
