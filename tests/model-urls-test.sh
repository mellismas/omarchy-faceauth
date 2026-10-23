#!/bin/bash
# Every URL in the model manifest answers 200, and each model's download is
# the size the manifest gives. The models package and `faceauth models fetch`
# download from these addresses, so a file moved, deleted or replaced there
# fails here first (B2). HEAD requests only, redirects followed; a server
# that gives no length is checked for its 200 alone.
#
#   tests/model-urls-test.sh [path/to/models.toml]
set -uo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
manifest=${1:-$here/../models.toml}
[[ -f $manifest ]] || { echo "not ok - no manifest at $manifest"; exit 1; }
fails=0
check() { if [[ $1 == "$2" ]]; then echo "ok - $3"; else echo "not ok - $3 (got '$1', want '$2')"; fails=$((fails+1)); fi; }

# One line per URL: the URL, then the size for a model's own url, or "-" for
# its license text.
entries=$(awk '
  function value() { v = $0; sub(/^[^"]*"/, "", v); sub(/".*$/, "", v); return v }
  /^\[\[model\]\]/ { if (url != "") print url, size; url = ""; size = "-" }
  /^url *=/ { url = value() }
  /^size *=/ { size = $3 }
  /^license_url *=/ { print value(), "-" }
  END { if (url != "") print url, size }
' "$manifest")
check "$(grep -c '^\[\[model\]\]' "$manifest")" "$(awk '$2 != "-"' <<< "$entries" | wc -l)" "every model in the manifest has a url and a size"

while read -r url size; do
  got=$(curl -sS -o /dev/null -I -L --retry 3 --max-time 60 -w '%{http_code} %header{content-length}' "$url")
  check "${got%% *}" "200" "$url answers 200"
  length=${got#* }
  if [[ $size != "-" && $length =~ ^[0-9]+$ ]]; then
    check "$length" "$size" "$url is $size bytes"
  fi
done <<< "$entries"
[[ $fails -eq 0 ]]
