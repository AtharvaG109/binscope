#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  cat <<'EOF'
Usage:
  scripts/find-test-binaries.sh <dir> [<dir> ...]

Examples:
  scripts/find-test-binaries.sh ~/Downloads
  scripts/find-test-binaries.sh /mnt/windows/System32 /mnt/linux/usr/bin

This scans for files that look like PE ("MZ") or ELF binaries.
EOF
  exit 1
fi

for root in "$@"; do
  if [[ ! -d "$root" ]]; then
    echo "Skipping non-directory: $root" >&2
    continue
  fi

  while IFS= read -r -d '' file; do
    magic=$(LC_ALL=C dd if="$file" bs=4 count=1 2>/dev/null | od -An -t x1 | tr -d ' \n')
    case "$magic" in
      4d5a* )
        printf 'PE   %s\n' "$file"
        ;;
      7f454c46 )
        printf 'ELF  %s\n' "$file"
        ;;
    esac
  done < <(find "$root" -type f -size +0c -print0 2>/dev/null)
done
