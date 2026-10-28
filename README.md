# Reduced-round KeeLoq with Z3

This project generates synthetic KeeLoq plaintext–ciphertext pairs and models encryption as Boolean constraints to explore key recovery. It runs a published 528-round test vector before each experiment. Bit 0 is the least significant bit; the register shifts right, the nonlinear function is `0x3A5C742E`, and round `r` uses key bit `r mod 64`.

Cipher specification and independent test vector: [KeeLoq cipher description and test vector](https://en.wikipedia.org/wiki/KeeLoq). The full-round vector is key `5CEC6701B79FD949`, plaintext `F741E2DB`, ciphertext `E44F4CDF`.

## Run

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python keeloq_demo.py --mode unknown-key --rounds 64 --pairs 4 --seed 1 --timeout 10000
python keeloq_demo.py --mode known-bits --rounds 64 --pairs 4 --seed 1 --timeout 10000
```

The timeout is in milliseconds **per solver check**; zero means unlimited. The uniqueness check is a second solve with the candidate excluded. SAT there means another key fits; UNSAT establishes uniqueness given the supplied observations and assumptions; UNKNOWN means uniqueness unknown. A candidate is checked with the concrete cipher, and comparison with the synthetic secret is reported separately. If the initial result is UNKNOWN or UNSAT, no candidate or uniqueness claim is made. Timings and outcomes depend on the machine, solver version, data, and parameters.

In unknown-key mode all 64 bits are unknown. In known-bits mode, bits 0 through 15 of the synthetic key are **supplied information**, not recovered by the attack. This is a conditional problem with 48 unknown bits. Guessing those 16 bits instead requires accounting for up to 2^16 hypotheses and their solver costs. With fewer than 64 rounds, key bits at indices from the round count through 63 are never used and cannot be recovered from the observations; a full key cannot be unique unless all unused bits are supplied as assumptions. More pairs may constrain a key more tightly, but do not guarantee a fast solve.

These synthetic reduced-round experiments do not demonstrate a practical attack on full 528-round KeeLoq or establish a general reduction of its security from 64 bits to 48 bits. A solver result for a particular instance and timeout is not a general complexity or security result.

Run the regression checks with `python -m unittest discover -s tests -v`.
