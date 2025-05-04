#!/usr/bin/env bash
set -euo pipefail

SEARCH_WORD="$1"
REPLACE_WORD="$2"
REPO_DIR="/home/phaedrus/.GH/Qompass/Rust/volta"

cd "$REPO_DIR"

# Grep all matches and loop through them with confirmation
grep -rl --exclude-dir=".git" --binary-files=without-match -- "$SEARCH_WORD" . | while read -r file; do
    matches=$(grep -n --color=always -F "$SEARCH_WORD" "$file")
    if [[ -n "$matches" ]]; then
        echo -e "\n🔍 Found in $file:\n$matches"
        read -p "❓ Replace '$SEARCH_WORD' with '$REPLACE_WORD' in this file? [y/N] " yn
        case "$yn" in
            [Yy]* )
                sed -i "s/\b$SEARCH_WORD\b/$REPLACE_WORD/g" "$file"
                echo "✅ Replaced in $file"
                ;;
            * )
                echo "⏭️ Skipped $file"
                ;;
        esac
    fi
done
