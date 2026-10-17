#!/bin/sh
# The table of the README's comparison: this crate and go-gtp, whose
# version compare/go.mod pins and `go build` fetches, on the same G-PDUs.
#
#   benches/compare.sh [core]
#
# Each case runs on one core (3 by default), three times; the table has the
# lowest time. Cycles and instructions per operation are those of perf
# stat, between a run of N operations and one of 2N, which leaves out the
# start of each program: PERF="sudo -n perf" where the kernel keeps perf
# from users (kernel.perf_event_paranoid above 2). Needs cargo and go.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
core=${1:-3}
perf=${PERF:-perf}
target=${CARGO_TARGET_DIR:-$here/target}
scratch=$(mktemp -d)
trap 'rm -r "$scratch"' EXIT

cargo build --quiet --release --manifest-path "$here/Cargo.toml" --bin compare
(cd "$here/compare" && go build -buildvcs=false -o "$scratch/gogtp" .)
ours=$target/release/compare
theirs=$scratch/gogtp

# The lowest of three runs: ns/op allocations/op octets/op max-rss-KiB.
measure() { # program case iterations
	for _ in 1 2 3; do taskset -c "$core" "$1" "$2" "$3"; done |
		sort -k3,3n | head -1 | cut -d' ' -f3-
}

# Cycles and instructions per operation.
counted() { # program case iterations
	for n in "$3" $(($3 * 2)); do
		$perf stat -x, -e cycles,instructions -o "$scratch/perf" \
			taskset -c "$core" "$1" "$2" "$n" >/dev/null
		awk -F, '$3 ~ /^(cycles|instructions)/ { printf "%s ", $1 }' "$scratch/perf"
		echo
	done | awk -v n="$3" 'NR == 1 { c = $1; i = $2 } NR == 2 { printf "%.0f %.0f", ($1 - c) / n, ($2 - i) / n }'
}

echo "load before: $(cut -d' ' -f1-3 /proc/loadavg)"
echo
echo "| Case | | ns | cycles | instructions | allocations | octets allocated | peak memory KiB | time against this crate |"
echo "|---|---|---|---|---|---|---|---|---|"
for case in encode-plain encode-container decode-plain decode-container round-trip; do
	case $case in round-trip) n=20000 ;; *) n=5000000 ;; esac
	mine=""
	for side in ours theirs; do
		eval program=\$$side
		set -- $(measure "$program" "$case" "$n") $(counted "$program" "$case" "$n" 2>/dev/null || echo - -)
		name=oxirush-gtp-u
		[ "$side" = theirs ] && name="go-gtp v0.8.12"
		[ -z "$mine" ] && mine=$1
		ratio=$(awk -v a="$1" -v b="$mine" 'BEGIN { printf "%.2f", a / b }')
		echo "| $case | $name | $1 | $5 | $6 | $2 | $3 | $4 | $ratio |"
	done
done
echo
echo "load after: $(cut -d' ' -f1-3 /proc/loadavg)"
