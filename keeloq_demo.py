#!/usr/bin/env python3
"""Reduced-round KeeLoq key-recovery experiment; not a full-round attack."""
import argparse
import random
import time

import z3

NLF = 0x3A5C742E
VECTOR_KEY = 0x5CEC6701B79FD949
VECTOR_PLAIN = 0xF741E2DB
VECTOR_CIPHER = 0xE44F4CDF


def encrypt(block, key, rounds=528):
    """KeeLoq encryption, with bit 0 the least significant bit."""
    for r in range(rounds):
        index = sum(((block >> bit) & 1) << i for i, bit in enumerate((1, 9, 20, 26, 31)))
        feedback = ((block >> 0) ^ (block >> 16) ^ (key >> (r % 64)) ^ (NLF >> index)) & 1
        block = (block >> 1) | (feedback << 31)
    return block


def recover(pairs, rounds, supplied_bits, timeout_ms):
    """Solve only from observed pairs and a mapping of supplied key-bit indices to values."""
    key = [z3.Bool(f'k_{i}') for i in range(64)]
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    for i, value in supplied_bits.items():
        solver.add(key[i] == bool(value))
    for p, (plain, cipher) in enumerate(pairs):
        state = [z3.BoolVal(bool((plain >> i) & 1)) for i in range(32)]
        for r in range(rounds):
            # NLF table is indexed by state bits 1, 9, 20, 26, 31 (LSB first).
            inputs = [state[i] for i in (1, 9, 20, 26, 31)]
            table = [z3.BoolVal(bool((NLF >> i) & 1)) for i in range(32)]
            for bit in inputs:
                table = [z3.If(bit, table[i+1], table[i]) for i in range(0, len(table), 2)]
            new_bit = z3.Bool(f's_{p}_{r}')
            # Shift right; the new MSB is bit 0 XOR bit 16 XOR scheduled key XOR NLF.
            solver.add(new_bit == z3.Xor(z3.Xor(state[0], state[16]), z3.Xor(key[r % 64], table[0])))
            state = state[1:] + [new_bit]
        solver.add(*[state[i] == bool((cipher >> i) & 1) for i in range(32)])
    start = time.monotonic()
    result = solver.check()
    elapsed = time.monotonic() - start
    if result != z3.sat:
        return str(result), elapsed, None, None, None, solver.reason_unknown() if result == z3.unknown else None
    model = solver.model()
    candidate = sum((1 << i) for i, bit in enumerate(key) if z3.is_true(model.eval(bit, model_completion=True)))
    # Exclude the complete candidate, including bits unused by the cipher.
    solver.add(z3.Or(*[bit != bool((candidate >> i) & 1) for i, bit in enumerate(key)]))
    start = time.monotonic()
    unique_result = solver.check()
    unique_elapsed = time.monotonic() - start
    reason = solver.reason_unknown() if unique_result == z3.unknown else None
    return str(result), elapsed, candidate, str(unique_result), unique_elapsed, reason


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('unknown-key', 'known-bits'), default='unknown-key')
    parser.add_argument('--rounds', type=int, default=64)
    parser.add_argument('--pairs', type=int, default=4)
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--timeout', type=int, default=10000, help='timeout in milliseconds per solver check (0 means unlimited)')
    args = parser.parse_args()
    if args.rounds < 1 or args.pairs < 1 or args.timeout < 0:
        parser.error('rounds and pairs must be positive; timeout must be nonnegative')
    actual = encrypt(VECTOR_PLAIN, VECTOR_KEY)
    print(f'Published 528-round vector: {actual:08X} (expected {VECTOR_CIPHER:08X}): {"PASS" if actual == VECTOR_CIPHER else "FAIL"}', flush=True)
    if actual != VECTOR_CIPHER:
        raise SystemExit(1)
    rng = random.Random(args.seed)
    secret = rng.getrandbits(64)
    pairs = [(p, encrypt(p, secret, args.rounds)) for p in (rng.getrandbits(32) for _ in range(args.pairs))]
    supplied = {i: (secret >> i) & 1 for i in range(16)} if args.mode == 'known-bits' else {}
    print(f'mode={args.mode} rounds={args.rounds} pairs={args.pairs} seed={args.seed} timeout_ms={args.timeout}', flush=True)
    if supplied:
        print('Supplied information: key bits 0..15 (16 correct bits); 48 bits remain unknown.', flush=True)
    if args.rounds < 64:
        print(f'Key bits {args.rounds}..63 are unused and cannot be recovered from these observations.', flush=True)
    status, elapsed, candidate, unique, unique_elapsed, reason = recover(pairs, args.rounds, supplied, args.timeout)
    print(f'Solver: {status.upper()} ({elapsed:.3f} s)')
    if candidate is None:
        if reason: print(f'Reason: {reason}')
        return
    verified = all(encrypt(p, candidate, args.rounds) == c for p, c in pairs)
    print(f'Candidate: {candidate:016X}; concrete verification: {"PASS" if verified else "FAIL"}')
    print(f'Candidate equals synthetic secret: {"yes" if candidate == secret else "no"} (experimental comparison)')
    print(f'Uniqueness: {"unique" if unique == "unsat" else "not unique" if unique == "sat" else "uniqueness unknown"} ({unique_elapsed:.3f} s; second solver result: {unique.upper()})')
    if reason: print(f'Uniqueness reason: {reason}')
    if not verified: raise SystemExit(1)

if __name__ == '__main__':
    main()
