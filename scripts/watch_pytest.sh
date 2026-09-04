#!/usr/bin/env bash
# Stall watchdog for a long pytest run.
#
# A hung run is silent: an xdist controller whose workers have died waits
# forever at 0% CPU. Measured once at 48 minutes before anyone noticed. A
# per-test --timeout does not catch it, because no test is running.
#
# Design notes, each earned by a false positive in an earlier version:
#
#   * Watch a PID, never a process-name grep. `ps | grep pytest` also matches
#     the shell wrapper (whose command line contains the invocation) and
#     zombies awaiting reap — both sit at 0% CPU and look exactly like a hang.
#   * Do not use CPU as a signal. Tk tests park in the event loop on after()
#     timers at genuinely ~0% CPU, and `ps` reports a lifetime average that
#     reads near zero for short runs anyway.
#   * Output growth is the only trustworthy liveness signal, and it only
#     works if the run is UNBUFFERED — launch it as `python -u -m pytest`.
#
# Usage:
#   python -u -m pytest ... > out.txt 2>&1 &
#   scripts/watch_pytest.sh out.txt $! [interval] [max_minutes]
set -uo pipefail

OUT="${1:?usage: watch_pytest.sh <output-file> <pid> [interval] [max_minutes]}"
PID="${2:?need the pid of the pytest run}"
INTERVAL="${3:-30}"
MAX_MIN="${4:-45}"
STALL_SAMPLES="${STALL_SAMPLES:-6}"

idle=0
last_size=-1
elapsed=0

while kill -0 "$PID" 2>/dev/null; do
  if [ "$elapsed" -ge $(( MAX_MIN * 60 )) ]; then
    echo "TIMEOUT: pid $PID still running after ${MAX_MIN} minutes"
    exit 3
  fi

  size=$(wc -c < "$OUT" 2>/dev/null || echo 0)
  if [ "$size" -eq "$last_size" ]; then
    idle=$(( idle + 1 ))
  else
    idle=0
  fi
  last_size=$size

  if [ "$idle" -ge "$STALL_SAMPLES" ]; then
    echo "STALLED: pid $PID alive but no output for $(( idle * INTERVAL ))s (stuck at ${size} bytes)"
    echo "  If the run is buffered this is a false alarm — relaunch with 'python -u -m pytest'."
    exit 2
  fi

  echo "running ${elapsed}s: ${size} bytes, idle ${idle}/${STALL_SAMPLES}"
  sleep "$INTERVAL"
  elapsed=$(( elapsed + INTERVAL ))
done

echo "pytest (pid $PID) finished after ${elapsed}s"
exit 0
