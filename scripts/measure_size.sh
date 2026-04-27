#!/usr/bin/env bash
set -euo pipefail

# Measure mzmq binary size across feature combinations for host and
# thumbv7em-none-eabihf targets. Emits two markdown tables to stdout.
#
# Both measurements build sizing/ (a thin bin crate that references every
# public mzmq API) as a fully linked binary, then sum `.text*` + `.rodata*`
# (ELF) or `__TEXT.__text` + `__TEXT.__const` (Mach-O) sections with
# `llvm-size -A`. Host uses the sizing crate with std; embedded uses
# cortex-m-rt for the reset vector + link script and builds no_std.
#
# An empty baseline binary (`sizing_baseline`) measures the fixed runtime
# overhead (startup, panic machinery, rt code) so the table reports only
# what mzmq itself contributes.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

LLVM_SIZE="$(command -v llvm-size || true)"
if [ -z "$LLVM_SIZE" ] && [ -x "/opt/homebrew/opt/llvm/bin/llvm-size" ]; then
    LLVM_SIZE="/opt/homebrew/opt/llvm/bin/llvm-size"
fi
if [ -z "$LLVM_SIZE" ]; then
    echo "error: llvm-size not found on PATH; install llvm (e.g. brew install llvm) and ensure its bin dir is on PATH, or use /opt/homebrew/opt/llvm/bin" >&2
    exit 1
fi

# Sum sizes of sections whose names start with any of the given prefixes
# (exact match or prefix + "."). Works for both ELF (.text, .rodata) and
# Mach-O (__text, __const under __TEXT segment printed by llvm-size -A).
sum_sections() {
    local file="$1"; shift
    "$LLVM_SIZE" -A "$file" | awk -v prefixes="$*" '
        BEGIN { n = split(prefixes, p, " ") }
        /^Total/ { next }
        /^section/ { next }
        {
            for (i = 1; i <= n; i++) {
                if ($1 == p[i] || index($1, p[i] ".") == 1) {
                    total += $2
                    next
                }
            }
        }
        END { print total + 0 }
    '
}

build_sizing() {
    local target_flag="$1"    # empty for host, or "--target=<triple>"
    local bin_name="$2"       # mzmq-sizing | mzmq-sizing-baseline
    local features="$3"

    # `sizing/.cargo/config.toml` provides `-C link-arg=-Tlink.x` for
    # bare-metal targets, but cargo only reads `.cargo/config.toml` relative
    # to cwd. Run from inside `sizing/` so that config is picked up.
    (
        cd "$REPO_ROOT/sizing"
        cargo build --release --quiet \
            --bin "$bin_name" \
            $target_flag \
            ${features:+--features "$features"}
    )

    if [ -n "$target_flag" ]; then
        local triple="${target_flag#--target=}"
        echo "$REPO_ROOT/sizing/target/$triple/release/$bin_name"
    else
        echo "$REPO_ROOT/sizing/target/release/$bin_name"
    fi
}

# Picks the right section prefixes for the target triple.
prefixes_for() {
    case "$1" in
        *-apple-*)   echo "__text __const" ;;
        *)           echo ".text .rodata" ;;
    esac
}

measure_combo() {
    local target_flag="$1"    # --target=<triple> or empty
    local features="$2"
    local host_triple="$3"    # triple string for prefix selection

    local probe baseline
    probe="$(build_sizing "$target_flag" "mzmq-sizing" "$features")"
    baseline="$(build_sizing "$target_flag" "mzmq-sizing-baseline" "")"
    local prefixes
    prefixes="$(prefixes_for "$host_triple")"

    local probe_bytes baseline_bytes
    probe_bytes="$(sum_sections "$probe" $prefixes)"
    baseline_bytes="$(sum_sections "$baseline" $prefixes)"
    echo $((probe_bytes - baseline_bytes))
}

emit_table() {
    local target_flag="$1"
    local host_triple="$2"
    shift 2
    local combos=("$@")
    local values=()
    for combo in "${combos[@]}"; do
        v="$(measure_combo "$target_flag" "$combo" "$host_triple")"
        values+=("$v")
    done
    local base="${values[0]}"
    for i in "${!combos[@]}"; do
        local v="${values[$i]}"
        local delta=$((v - base))
        local sign=""
        if [ "$delta" -gt 0 ]; then sign="+"; fi
        printf "| \`%s\` | %'d | %s%'d |\n" "${combos[$i]}" "$v" "$sign" "$delta"
    done
}

rustc_vv="$(rustc -vV)"
host_triple="$(echo "$rustc_vv" | awk '/^host:/ {print $2}')"

echo "## Toolchain & build options"
echo ""
echo '```'
echo "# rustc"
echo "$rustc_vv"
echo ""
echo "# cargo"
cargo -V
echo ""
echo "# sizing/Cargo.toml [profile.release]"
awk '/^\[profile\.release\]/{flag=1; print; next} /^\[/{flag=0} flag' "$REPO_ROOT/sizing/Cargo.toml"
echo ""
echo "# sizing/.cargo/config.toml [target.thumbv7em-none-eabihf]"
awk '/^\[target\.thumbv7em-none-eabihf\]/{flag=1; print; next} /^\[/{flag=0} flag' "$REPO_ROOT/sizing/.cargo/config.toml"
echo ""
echo "# cargo build invocation (per combo)"
echo 'cargo build --release --bin <mzmq-sizing|mzmq-sizing-baseline> [--target=<triple>] [--features <...>]'
echo '```'
echo ""

echo "## Host (\`$host_triple\`, Mach-O \`__TEXT\` code+const, bytes)"
echo ""
echo "Baseline (empty \`fn main\`) subtracted to isolate mzmq's contribution."
echo ""
printf "| Features | bytes | Δ vs sync |\n"
printf "|---|---:|---:|\n"
emit_table "" "$host_triple" \
    "sync" "async" "sync,plain" "async,plain" "sync,std" "async,std" "sync,async,plain,std"

echo ""
echo "## Embedded (\`thumbv7em-none-eabihf\`, ELF \`.text + .rodata\`, bytes)"
echo ""
echo "Baseline (cortex-m-rt reset vector + empty entry) subtracted to isolate"
echo "mzmq's contribution. Panic handler (loop) is trivial and shared."
echo ""
printf "| Features | bytes | Δ vs sync |\n"
printf "|---|---:|---:|\n"
emit_table "--target=thumbv7em-none-eabihf" "thumbv7em-none-eabihf" \
    "sync" "async" "sync,plain" "async,plain"
