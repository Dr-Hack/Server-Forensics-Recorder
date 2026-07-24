#!/usr/bin/env bash
# Tests for web request attribution.
#
# The driving case is incident-20260725-001537: a sustained PHP saturation on a
# single-account cPanel box behind Cloudflare, where the load was a flood against
# WordPress admin-ajax.php / admin-post.php. The process capture named the script;
# these functions must name the URL and expose that the client IPs are Cloudflare
# edges, not the attacker.
#
# The window filter is tested with explicit sortable stamps rather than through
# the epoch conversion, on purpose: web_epoch_to_stamp uses the host's local
# timezone, which matches the domlogs ONLY on the target host. Keeping the parser
# timezone-free is what makes it testable here at all.
#
# No root, no /proc, no web server, no sysstat.
# shellcheck disable=SC2034
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

# shellcheck source=../lib/utils.sh
source "${ROOT_DIR}/lib/utils.sh"
# shellcheck source=../lib/webforensics.sh
source "${ROOT_DIR}/lib/webforensics.sh"

WORK="$(mktemp -d 2>/dev/null || mktemp -d -t sf-web)"
trap 'rm -rf -- "$WORK"' EXIT

WEBLOG_TOP_ROWS=20
WEBLOG_ABUSE_ENDPOINTS="xmlrpc.php wp-login.php admin-ajax.php admin-post.php wp-cron.php"

FAILURES=0
pass() { printf '  ok   %s\n' "$1"; }
fail() {
    printf '  FAIL %s\n' "$1"
    FAILURES=$((FAILURES + 1))
}
assert_eq() {
    local got="$1" want="$2" desc="$3"
    if [[ "$got" == "$want" ]]; then pass "$desc"; else fail "$desc (got '${got}', want '${want}')"; fi
}
assert_contains() {
    local hay="$1" needle="$2" desc="$3"
    if [[ "$hay" == *"$needle"* ]]; then pass "$desc"; else fail "$desc (missing: ${needle})"; fi
}
refute_contains() {
    local hay="$1" needle="$2" desc="$3"
    if [[ "$hay" != *"$needle"* ]]; then pass "$desc"; else fail "$desc (unexpected: ${needle})"; fi
}

# --- Cloudflare classification ------------------------------------------------

printf 'Cloudflare IP classification\n'
for ip in 162.158.158.118 104.23.190.52 172.71.203.142 172.70.111.86 141.101.64.5 108.162.200.1; do
    if web_ip_is_cloudflare "$ip"; then pass "recognises Cloudflare edge ${ip}"; else fail "should recognise Cloudflare ${ip}"; fi
done
for ip in 203.0.113.9 8.8.8.8 39.50.216.10 192.0.2.1; do
    if web_ip_is_cloudflare "$ip"; then fail "must not flag non-Cloudflare ${ip}"; else pass "leaves non-Cloudflare ${ip} alone"; fi
done

# --- window filtering + field extraction --------------------------------------

printf 'window filter and field extraction\n'
# Combined log format. Two lines are outside the 00:14:00-00:20:00 window; the
# last uses a restored real client IP in the first field to prove the request and
# UA are lifted by quote-splitting, not by fixed column position.
cat >"${WORK}/access.log" <<'LOG'
162.158.158.118 - - [25/Jul/2026:00:13:30 +0500] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 511 "-" "early-bot"
162.158.158.118 - - [25/Jul/2026:00:14:20 +0500] "POST /wp-admin/admin-ajax.php?action=heartbeat HTTP/1.1" 200 1234 "https://cryptoawaz.com/" "Mozilla/5.0 flood"
104.23.190.52 - - [25/Jul/2026:00:15:05 +0500] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 1200 "-" "Mozilla/5.0 flood"
162.158.158.118 - - [25/Jul/2026:00:16:00 +0500] "POST /wp-admin/admin-post.php HTTP/1.1" 302 0 "-" "Mozilla/5.0 flood"
172.71.203.142 - - [25/Jul/2026:00:17:10 +0500] "GET /index.php HTTP/1.1" 200 8000 "-" "Mozilla/5.0 flood"
162.158.158.118 - - [25/Jul/2026:00:18:44 +0500] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0 flood"
203.0.113.9 - - [25/Jul/2026:00:19:00 +0500] "GET /wp-login.php HTTP/1.1" 200 4096 "-" "curl/8.0"
162.158.158.118 - - [25/Jul/2026:00:25:00 +0500] "GET /index.php HTTP/1.1" 200 700 "-" "late-bot"
LOG

FILTERED="$(web_filter_window 20260725001400 20260725002000 <"${WORK}/access.log")"

nrows="$(printf '%s\n' "$FILTERED" | grep -c . || true)"
assert_eq "$nrows" "6" "only the six in-window lines survive"
refute_contains "$FILTERED" "early-bot" "the pre-window line is dropped"
refute_contains "$FILTERED" "late-bot" "the post-window line is dropped"

row1="$(printf '%s\n' "$FILTERED" | head -n 1)"
assert_eq "$(printf '%s' "$row1" | cut -f2)" "162.158.158.118" "client IP is extracted"
assert_eq "$(printf '%s' "$row1" | cut -f3)" "200" "status is extracted from the right field"
assert_eq "$(printf '%s' "$row1" | cut -f4)" "POST" "method is extracted"
assert_eq "$(printf '%s' "$row1" | cut -f5)" "/wp-admin/admin-ajax.php" "query string is stripped from the path"
assert_eq "$(printf '%s' "$row1" | cut -f6)" "Mozilla/5.0 flood" "user agent is extracted by quote-splitting"

realip_row="$(printf '%s\n' "$FILTERED" | awk -F'\t' '$2=="203.0.113.9"')"
assert_eq "$(printf '%s' "$realip_row" | cut -f5)" "/wp-login.php" "path is lifted correctly even for a restored real IP line"

# --- reporting ----------------------------------------------------------------

printf 'request report\n'
REPORT="$(printf '%s\n' "$FILTERED" | web_report)"
assert_contains "$REPORT" "Requests in window: 6" "report counts the in-window requests"
assert_contains "$REPORT" "/wp-admin/admin-ajax.php" "report lists the abused path"

# admin-ajax.php (3 hits) must lead the top-paths table.
top_path="$(printf '%s\n' "$REPORT" | awk '/Top request paths/{f=1;next} f&&NF{print $2; exit}')"
assert_eq "$top_path" "/wp-admin/admin-ajax.php" "the most-hit path leads the table"

assert_contains "$REPORT" "admin-ajax.php" "abuse-endpoint tally names admin-ajax"
abuse_ajax="$(printf '%s\n' "$REPORT" | awk '/Known-abuse endpoints/{f=1;next} f && /admin-ajax.php/{print $1; exit}')"
assert_eq "$abuse_ajax" "3" "abuse tally counts all three admin-ajax hits"

assert_contains "$REPORT" "Cloudflare edges" "report warns that the client IPs are Cloudflare"
assert_contains "$REPORT" "CF-Connecting-IP" "report points at the header that carries the real IP"
assert_contains "$REPORT" "Block abusive traffic at Cloudflare" "report advises blocking at the CDN, not CSF"

# When the traffic is NOT behind a CDN, the caveat must not appear.
printf 'report without a CDN\n'
cat >"${WORK}/direct.log" <<'LOG'
203.0.113.9 - - [25/Jul/2026:00:15:00 +0500] "GET /index.php HTTP/1.1" 200 900 "-" "curl/8.0"
198.51.100.7 - - [25/Jul/2026:00:16:00 +0500] "GET /index.php HTTP/1.1" 200 900 "-" "curl/8.0"
LOG
DIRECT_REPORT="$(web_filter_window 20260725001400 20260725002000 <"${WORK}/direct.log" | web_report)"
refute_contains "$DIRECT_REPORT" "Cloudflare edges" "no CDN caveat when client IPs are real"

# An empty window explains itself rather than erroring.
printf 'empty window\n'
EMPTY="$(printf '' | web_report || printf 'ERRORED')"
assert_contains "$EMPTY" "No access-log lines" "an empty window is reported, not an error"
refute_contains "$EMPTY" "ERRORED" "empty input does not fail the reporter"

# Malformed lines (no request quotes) must be skipped, not crash the filter.
printf 'malformed input\n'
MAL="$(printf 'garbage line with no brackets or quotes\n[not a real log]\n' \
    | web_filter_window 20260725001400 20260725002000 || printf 'ERRORED')"
assert_eq "${MAL:-empty}" "empty" "malformed lines yield no rows and no error"

if [[ "$FAILURES" -gt 0 ]]; then
    printf 'webforensics tests: %s failure(s)\n' "$FAILURES" >&2
    exit 1
fi
printf 'webforensics tests: all passed\n'
