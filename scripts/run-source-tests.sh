#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="$repo_root/zig-out/bin/ampl"
tests_dir="$repo_root/tests/sources"

echo "Building ampl..."
(cd "$repo_root" && zig build)

if [[ ! -d "$tests_dir" ]]; then
  echo "No source tests found at $tests_dir"
  exit 1
fi

shopt -s nullglob
sources=("$tests_dir"/*.ampl)
if [[ ${#sources[@]} -eq 0 ]]; then
  echo "No *.ampl tests in $tests_dir"
  exit 1
fi

fail=0
for src in "${sources[@]}"; do
  name="$(basename "${src%.ampl}")"
  expected_file="$tests_dir/$name.expected"
  if [[ ! -f "$expected_file" ]]; then
    echo "[$name] missing expected output: $expected_file"
    fail=1
    continue
  fi

  echo "[$name] running..."
  output="$("$bin" "$src")"
  expected="$(cat "$expected_file")"

  if [[ "$output" != "$expected" ]]; then
    echo "[$name] FAILED"
    echo "expected:"
    echo "$expected"
    echo "got:"
    echo "$output"
    fail=1
  else
    echo "[$name] ok"
  fi
done

if [[ $fail -ne 0 ]]; then
  echo "Some source tests failed."
  exit 1
fi

echo "All source tests passed."
