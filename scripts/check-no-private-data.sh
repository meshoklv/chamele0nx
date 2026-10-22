#!/usr/bin/env bash
# Fail if anything that belongs to a live deployment made it into the tree.
#
# Run it before every push:   scripts/check-no-private-data.sh
# CI runs it on every commit.
#
# The rule this enforces is in CONTRIBUTING.md: no real domains, no server
# addresses, no secrets, no certificate pins, no captured traffic profiles.
set -uo pipefail

cd "$(dirname "$0")/.."
fail=0

report() {
  printf '\n\033[31m%s\033[0m\n' "$1"
  shift
  printf '%s\n' "$@"
  fail=1
}

# Everything tracked by git, minus the licence and the dependency digests.
mapfile -t files < <(git ls-files -z | tr '\0' '\n' | grep -vE '^(LICENSE|go\.sum)$' || true)
[ "${#files[@]}" -eq 0 ] && { echo "no tracked files yet — nothing to check"; exit 0; }

# 1. Public IP addresses. Documentation ranges and private ranges are fine.
hits=$(grep -nHE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "${files[@]}" 2>/dev/null \
  | grep -vE '(127\.0\.0\.1|0\.0\.0\.0|1\.1\.1\.1|8\.8\.8\.8|8\.8\.4\.4|1\.2\.3\.4)' \
  | grep -vE '(10\.[0-9]|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)' \
  | grep -vE '(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)' \
  | grep -vE '(537\.36|146\.0\.0|147\.0\.3|/(8|12|16|24)\b)' \
  | grep -vE 'RFC ?[0-9]{3,5}' || true)   # spec section numbers look like IPs
[ -n "$hits" ] && report "Possible real IP addresses:" "$hits"

# is_reserved reports whether a name is one of the documentation domains RFC
# 2606 sets aside, or sits under one. Those can never belong to anybody, so
# listing each variant a test happens to use would be noise.
is_reserved() {
  case "$1" in
    example.com|example.net|example.org|*.example.com|*.example.net|*.example.org) return 0 ;;
    example|*.example|*.invalid|*.test|*.localhost) return 0 ;;
    *) return 1 ;;
  esac
}

# 2. Hostnames. Anything not in scripts/allowed-hosts.txt is suspect.
allow=$(grep -vE '^\s*(#|$)' scripts/allowed-hosts.txt | sed 's/[[:space:]]//g')
hits=$(grep -nHoE '\b[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+\.(ru|su|io|net|com|org|dev|xyz|online|site|app|me|info|cc|to|sh|uk|de|fr|nl|eu|top|tech|pro|biz|ch|it|es|pl|cz|tv|ai|co|us|in|jp|cn|kz|by|ua|ir|tr|gg|li|is|st|ws|re|fm|one|cloud|link|zone|team|host|space|store|life|world|group|digital|network|systems|solutions|agency)\b' "${files[@]}" 2>/dev/null \
  | while IFS= read -r line; do
      host=${line##*:}
      grep -qxF "$host" <<<"$allow" && continue
      is_reserved "$host" && continue
      printf '%s\n' "$line"
    done)
[ -n "$hits" ] && report "Hostnames not listed in scripts/allowed-hosts.txt:" "$hits"

# 2b. Single-label domains: rule 2 needs two dots and misses a bare "host.tld".
# Only TLDs that cannot be confused with a file extension are checked here.
hits=$(grep -nHoE '\b[a-z0-9][a-z0-9-]{2,}\.(ru|su|io|net|com|org|xyz|online|site|top|tech|host|cloud|space|store|world|digital|network|systems|solutions|agency|zone|link|team|life|group|info|biz|eu|uk|de|fr|nl|jp|cn|kz|ua|ir|tr|ch|es|cz)\b' "${files[@]}" 2>/dev/null \
  | while IFS= read -r line; do
      host=${line##*:}
      # "usenix.org" is the same organisation as the allowed "www.usenix.org",
      # so accept a match that any allowed host ends with.
      grep -qxF "$host" <<<"$allow" && continue
      is_reserved "$host" && continue
      grep -qE "(^|\.)${host//./\\.}$" <<<"$allow" && continue
      printf '%s\n' "$line"
    done)
[ -n "$hits" ] && report "Single-label hostnames not listed in scripts/allowed-hosts.txt:" "$hits"

# 3. Long hex or base64 blobs: secrets, keys, certificate pins.
hits=$(grep -nHE '"[A-Fa-f0-9]{40,}"' "${files[@]}" 2>/dev/null \
  | grep -vE '0123456789abcdef|00112233445566|deadbeef' || true)
[ -n "$hits" ] && report "Long hex literals — a secret or a key pin?" "$hits"

# 3b. Credentials that announce themselves by prefix or shape.
hits=$(grep -nHE '(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{20,}|[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})' \
  "${files[@]}" 2>/dev/null || true)
[ -n "$hits" ] && report "Credential-shaped strings (API token, bot token, JWT):" "$hits"

# 3c. Assignments that hand a literal to something named like a secret.
hits=$(grep -nHiE '(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"'[:space:]]{8,}' \
  "${files[@]}" 2>/dev/null \
  | grep -vE '(example|placeholder|changeme|redacted|xxxx|your[_-]|<|\$\{|os\.Getenv|flag\.String|test|dummy|sample)' || true)
[ -n "$hits" ] && report "A secret-looking name assigned a literal value:" "$hits"

# 4. Private key material.
hits=$(grep -nHE 'BEGIN ([A-Z]+ )*PRIVATE KEY' "${files[@]}" 2>/dev/null || true)
[ -n "$hits" ] && report "Private key material:" "$hits"

# 4b. Real e-mail addresses. Only documentation examples are allowed.
hits=$(grep -nHoE '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' "${files[@]}" 2>/dev/null \
  | grep -vE '@(example\.(com|org|net)|users\.noreply\.github\.com|localhost)\b' \
  | grep -vE '@[A-Za-z0-9.-]*\.example\.com\b' || true)
[ -n "$hits" ] && report "E-mail addresses — a real one identifies a person:" "$hits"

# 5. Local paths that reveal a developer machine.
hits=$(grep -nHE '(/(home|Users)/[a-zA-Z][a-zA-Z0-9_.-]*|[A-Za-z]:\\\\?Users\\\\?[a-zA-Z]|/root/\\.[a-z]|/root/(workspace|projects|Desktop|Downloads)/|/opt/[a-z][a-z0-9_-]*/(home|users)/)' "${files[@]}" 2>/dev/null \
  | grep -vE '/home/(user|username|youruser)\b' || true)
[ -n "$hits" ] && report "Absolute paths from a developer machine:" "$hits"

# 5b. Routable IPv6 addresses. Loopback and documentation prefixes are fine.
hits=$(grep -nHoE '\b([0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b' "${files[@]}" 2>/dev/null \
  | grep -E ':[0-9]*[a-fA-F]' \
  | grep -viE '(::1|0:0:0:0:0:0:0:1)$' \
  | grep -viE '(2001:0?db8|fe80|fc00|fd00|ff02)' || true)
[ -n "$hits" ] && report "Possible real IPv6 addresses:" "$hits"

# 6. Captured traffic profiles. Only the generic examples may be committed.
hits=$(git ls-files '*.json' | grep -vE '^(deploy/profiles/.*\.example\.json|\.github/repo-meta\.json)$' || true)
[ -n "$hits" ] && report "JSON files outside deploy/profiles/*.example.json — a captured profile?" "$hits"

# 7. The same credential shapes anywhere in the commit history. A secret that was
#    added and later deleted still ships to everyone who clones the repository.
if [ "${SKIP_HISTORY_SCAN:-0}" != "1" ]; then
  # A shallow clone has almost no history to scan, so this rule would pass
  # while proving nothing. Say so instead of reporting a green run: a CI
  # checkout defaults to fetch-depth 1, and that is exactly how this check
  # quietly stops working.
  if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = "true" ]; then
    report "Shallow clone: the commit history cannot be scanned." \
      "Fetch the full history (git fetch --unshallow, or fetch-depth: 0 in CI)," \
      "or set SKIP_HISTORY_SCAN=1 to state deliberately that you accept the gap."
  fi
  hits=$(git log --all -p --no-color 2>/dev/null \
    | grep -aE '^\+' \
    | grep -aoE '(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}|BEGIN ([A-Z]+ )*PRIVATE KEY)' \
    | sort -u || true)
  [ -n "$hits" ] && report "Credentials found in the commit history (rewriting the tree does not remove these):" "$hits"
fi

if [ "$fail" -eq 0 ]; then
  echo "clean: no private data found in tracked files or commit history"
else
  printf '\n\033[31mrefusing to pass. Remove the findings above, or narrow the rule that caught them.\033[0m\n'
fi
exit "$fail"
