#!/bin/bash
# 36 short runs (nt_, pf_, ntpf_ variants). 90 s / 3 GB limit each.
# Usage: ./run_variants.sh | tee results_variants.txt     (paste results_variants.txt back)
ulimit -v 3000000
for v in nt pf ntpf; do
 for n in r0_baseline r1_ecdh_broken r2_kem_broken r5a1_pub_static_kem_leaked r5a2_pub_static_ecdh_leaked \
   r5a3_pub_both_static_leaked r5b1_brk_static_kem_leaked r5b2_brk_static_ecdh_leaked r5b3_brk_both_static_leaked \
   r6_static_keys_leak_later r7_ecdh_later_plus_static_kem r8_kem_later_plus_static_ecdh; do
  f=${v}_$n
  echo "==================== $f ===================="
  timeout 90 proverif "$f.pv" 2>&1 | grep -E "^RESULT|rror"
  [ ${PIPESTATUS[0]} -eq 124 ] && echo "TIMEOUT after 90 s: $f"
 done
done
