#!/usr/bin/env bash
set -euo pipefail

cargo llvm-cov report --json --summary-only | jq -r '
  def pct(x): (x * 10 | round) / 10 | tostring + "%";
  def fmt(a; b): "\(a)/\(b)";
  (.cargo_llvm_cov.manifest_path | split("/") | .[:-1] | join("/") + "/") as $root |
  [
    "| File | Lines | Lines % | Functions | Funcs % | Regions | Regions % |",
    "|------|------:|--------:|----------:|--------:|--------:|----------:|"
  ] +
  [
    .data[0].files[] |
    "| `\(.filename | ltrimstr($root))` | \(fmt(.summary.lines.covered; .summary.lines.count)) | \(pct(.summary.lines.percent)) | \(fmt(.summary.functions.covered; .summary.functions.count)) | \(pct(.summary.functions.percent)) | \(fmt(.summary.regions.covered; .summary.regions.count)) | \(pct(.summary.regions.percent)) |"
  ] +
  [
    .data[0].totals |
    "| **Total** | **\(fmt(.lines.covered; .lines.count))** | **\(pct(.lines.percent))** | **\(fmt(.functions.covered; .functions.count))** | **\(pct(.functions.percent))** | **\(fmt(.regions.covered; .regions.count))** | **\(pct(.regions.percent))** |"
  ] | .[]
'
