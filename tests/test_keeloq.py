import unittest

from keeloq_demo import VECTOR_CIPHER, VECTOR_KEY, VECTOR_PLAIN, encrypt, recover


class KeeLoqTests(unittest.TestCase):
    def test_published_vector(self):
        self.assertEqual(encrypt(VECTOR_PLAIN, VECTOR_KEY), VECTOR_CIPHER)

    def test_recovery_matches_observations_and_is_unique(self):
        secret = 0x91B7584A2265B1F5
        plaintexts = [0x10203040, 0xABCDEF01, 0x76543210, 0xF2345678]
        pairs = [(p, encrypt(p, secret, 64)) for p in plaintexts]
        status, _, candidate, uniqueness, _, _ = recover(pairs, 64, {}, 10000)
        self.assertEqual(status, 'sat')
        self.assertTrue(all(encrypt(p, candidate, 64) == c for p, c in pairs))
        self.assertEqual(uniqueness, 'unsat')
        self.assertEqual(candidate, secret)

    def test_unused_key_bits_allow_multiple_keys(self):
        secret = 0x123456789ABCDEF0
        pairs = [(0x12345678, encrypt(0x12345678, secret, 8))]
        status, _, candidate, uniqueness, _, _ = recover(pairs, 8, {}, 10000)
        self.assertEqual(status, 'sat')
        self.assertEqual(encrypt(pairs[0][0], candidate, 8), pairs[0][1])
        self.assertEqual(uniqueness, 'sat')

    def test_contradictory_observations_are_unsatisfiable(self):
        cipher = encrypt(0x12345678, VECTOR_KEY, 32)
        status, _, candidate, uniqueness, _, _ = recover(
            [(0x12345678, cipher), (0x12345678, cipher ^ 1)], 32, {}, 10000
        )
        self.assertEqual(status, 'unsat')
        self.assertIsNone(candidate)
        self.assertIsNone(uniqueness)

    def test_known_key_bits_are_respected(self):
        secret = 0x123456789ABCDEF0
        pairs = [(0x12345678, encrypt(0x12345678, secret, 8))]
        supplied = {i: (secret >> i) & 1 for i in range(16)}
        status, _, candidate, _, _, _ = recover(pairs, 8, supplied, 10000)
        self.assertEqual(status, 'sat')
        self.assertEqual(candidate & 0xFFFF, secret & 0xFFFF)
        self.assertEqual(encrypt(pairs[0][0], candidate, 8), pairs[0][1])


if __name__ == '__main__':
    unittest.main()
