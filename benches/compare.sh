#!/bin/sh
# The table of the comparison in benches/README.md: this crate and go-gtp, whose
# version compare/go.mod pins and `go build` fetches, on the same G-PDUs.
#
#   benches/compare.sh [core]
#
# Each side of a case runs once a round, in turns, ROUNDS rounds (10 by
# default), on one core (3 by default), so that a busy moment of the machine
# falls on both. The table has the median time of the rounds and their
# spread, the lowest and the highest; the time of go-gtp against this
# crate's is the ratio of the medians, given only where the two spreads do
# not overlap. Cycles and instructions per operation are the median of those
# of perf stat, between a run of N operations and one of 2N in each round,
# which leaves out the start of each program: PERF="sudo -n perf" where the
# kernel keeps perf from users (kernel.perf_event_paranoid above 2). Needs
# cargo and go.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
core=${1:-3}
rounds=${ROUNDS:-10}
perf=${PERF:-perf}
target=${CARGO_TARGET_DIR:-$here/target}
scratch=$(mktemp -d)
trap 'rm -r "$scratch"' EXIT

cargo build --quiet --release --manifest-path "$here/Cargo.toml" --bin compare
(cd "$here/compare" && go build -buildvcs=false -o "$scratch/gogtp" .)
ours=$target/release/compare
theirs=$scratch/gogtp

# Cycles and instructions per operation.
counted() { # program case iterations
	for n in "$3" $(($3 * 2)); do
		$perf stat -x, -e cycles,instructions -o "$scratch/perf" \
			taskset -c "$core" "$1" "$2" "$n" >/dev/null
		awk -F, '$3 ~ /^(cycles|instructions)/ { printf "%s ", $1 }' "$scratch/perf"
		echo
	done | awk -v n="$3" 'NR == 1 { c = $1; i = $2 } NR == 2 { printf "%.0f %.0f", ($1 - c) / n, ($2 - i) / n }'
}

cases="encode-plain encode-container decode-plain decode-container round-trip"
rows=$scratch/rows
echo "load before: $(cut -d' ' -f1-3 /proc/loadavg); core $core, $rounds rounds"
round=0
while [ "$round" -lt "$rounds" ]; do
	for case in $cases; do
		case $case in round-trip) n=20000 ;; *) n=5000000 ;; esac
		for side in ours theirs; do
			eval program=\$$side
			# ns/op allocations/op octets/op max-rss-KiB, cycles, instructions
			set -- $(taskset -c "$core" "$program" "$case" "$n" | cut -d' ' -f3-) $(counted "$program" "$case" "$n" 2>/dev/null || echo - -)
			echo "$case|$side|$1|$2|$3|$4|$5|$6" >>"$rows"
		done
	done
	round=$((round + 1))
done

echo
echo "| Case | | ns | Lowest and highest | cycles | instructions | allocations | octets allocated | peak memory KiB | time against this crate |"
echo "|---|---|---|---|---|---|---|---|---|---|"
for case in $cases; do
	for side in ours theirs; do
		name=oxirush-gtp-u
		[ "$side" = theirs ] && name="go-gtp v0.8.12"
		awk -F'|' -v wanted="$case" -v side="$side" -v name="$name" '
			function median(list, count,    sorted, i, j, t) {
				for (i = 1; i <= count; i++) sorted[i] = list[i]
				for (i = 2; i <= count; i++)
					for (j = i; j > 1 && sorted[j - 1] + 0 > sorted[j] + 0; j--) {
						t = sorted[j]; sorted[j] = sorted[j - 1]; sorted[j - 1] = t
					}
				return count % 2 ? sorted[(count + 1) / 2] : (sorted[count / 2] + sorted[count / 2 + 1]) / 2
			}
			$1 != wanted { next }
			$2 == "ours" { ours[++o] = $3; if (o == 1 || $3 < ourlow) ourlow = $3; if (o == 1 || $3 > ourhigh) ourhigh = $3 }
			$2 == side {
				n++; ns[n] = $3; allocations[n] = $4; octets[n] = $5; peak[n] = $6; cycles[n] = $7; instructions[n] = $8
				if (n == 1 || $3 < low) low = $3
				if (n == 1 || $3 > high) high = $3
			}
			END {
				m = median(ns, n)
				ratio = ""
				if (side != "ours")
					ratio = (low > ourhigh || high < ourlow) ? sprintf("%.2f", m / median(ours, o)) : "spreads overlap"
				printf "| %s | %s | %.1f | %.1f to %.1f | %s | %s | %s | %s | %s | %s |\n", wanted, name, m, low, high,
					cycles[1] == "-" ? "-" : sprintf("%.0f", median(cycles, n)),
					instructions[1] == "-" ? "-" : sprintf("%.0f", median(instructions, n)),
					median(allocations, n), median(octets, n), median(peak, n), ratio
			}' "$rows"
	done
done
echo
echo "load after: $(cut -d' ' -f1-3 /proc/loadavg)"
