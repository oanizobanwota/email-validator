#!/usr/bin/env bash
# Copy the freshly built installers from ../dist into public/downloads with URL-safe names.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p public/downloads
rm -f public/downloads/*
for f in ../dist/*.exe ../dist/*.dmg; do
  [ -e "$f" ] || continue
  cp "$f" "public/downloads/$(basename "$f" | tr ' ' '-')"
done
ls -la public/downloads
