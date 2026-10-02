#!/bin/bash
# Safe runner: 90 s and ~3 GB limit per model, so one hard model cannot freeze your screen.
# Usage: ./run_real.sh | tee results_real.txt     (r3 is optional, see README)
ulimit -v 3000000
for f in r0_baseline r1_ecdh_broken r2_kem_broken \
  r5a1_pub_static_kem_leaked r5a2_pub_static_ecdh_leaked r5a3_pub_both_static_leaked \
  r5b1_brk_static_kem_leaked r5b2_brk_static_ecdh_leaked r5b3_brk_both_static_leaked \
  r6_static_keys_leak_later r6l_static_keys_leak_later_late \
  r4a_ecdh_broken_later r4b_kem_broken_later r4c_both_broken_later \
  r7_ecdh_later_plus_static_kem r8_kem_later_plus_static_ecdh r9_everything_later; do
  echo "==================== $f ===================="
  timeout 90 proverif "$f.pv" 2>&1 | grep -E "^RESULT|rror"
  [ ${PIPESTATUS[0]} -eq 124 ] && echo "TIMEOUT after 90 s: $f"
done
