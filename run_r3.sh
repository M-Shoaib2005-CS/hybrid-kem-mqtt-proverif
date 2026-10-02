#!/bin/bash
# R3 (both primitives broken during the run). Tries the full model first, then smaller ones.
# Usage: ./run_r3.sh 2>&1 | tee results_r3.txt
ulimit -v 6000000   # ~6 GB cap; raise if you have more RAM
for f in r3_both_broken_1session r3_both_broken_1broker r3_both_broken; do
  echo "==================== $f (limit 1800 s) ===================="
  /usr/bin/time -v timeout 1800 proverif "$f.pv" > "$f.out" 2> "$f.time"
  rc=$?
  grep -E "^RESULT|rror" "$f.out"
  [ $rc -eq 124 ] && echo "TIMEOUT after 1800 s: $f"
  grep -E "Elapsed|Maximum resident" "$f.time"
done
