# Hybrid KEM-MQTT handshake: ProVerif models

Symbolic models (ProVerif, Dolev-Yao) of the Hybrid KEM-MQTT handshake of Dong et al. (IACR TCHES 2026(2):372-408),
as drawn in Figure 2 of that paper. They accompany the paper *A Symbolic Analysis of the Hybrid KEM-MQTT Handshake
under Component Compromise*.

## Contents
- `r*.pv`: base scenarios R0 to R9 (R6l = R6 with the broker sending its data after the publisher is confirmed).
- `nt_*.pv`: variants without the transcript hash in the key derivation.
- `pf_*.pv`: variants where the publisher confirms first. `ntpf_*.pv`: both changes.
- `gen_real.py`: generate all models. Regenerate with `python3 gen_real.py`.
- `run_real.sh`, `run_variants.sh`: run ProVerif on every model (90 s and about 3 GB limit each).
- `run_r3.sh`, `r3_both_broken*.pv`: scenario R3 (both primitives broken during the run). It did not finish in
  90 s or in a 30-minute run, so it is excluded from the results (R4c and R9 cover the all-broken case).
- `check_real.py`, `check_variants.py`: compare ProVerif output with the expected results.

## Reproduce
```
./run_real.sh | tee results_real.txt
python3 check_real.py
./run_variants.sh | tee results_variants.txt
python3 check_variants.py
```
Requires ProVerif and Python 3. Tested on Ubuntu under WSL.

## Scope
Symbolic model only: perfect cryptography, no implementation, side-channel or computational guarantees.
The model follows Figure 2 of the paper, not the authors' open-source code. See the paper for simplifications.
