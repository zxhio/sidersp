#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

mapfile -t headers < <(
	clang -target bpf -O2 -g -Wall -M bpf/prog.c \
		| tr ' \\\n' '\n' \
		| sed '/^$/d' \
		| rg '^/usr/include/' \
		| sort -u
)

for src in "${headers[@]}"; do
	rel=${src#/usr/include/}
	dst="bpf/${rel}"
	mkdir -p "$(dirname "$dst")"
	cp -L "$src" "$dst"
done
