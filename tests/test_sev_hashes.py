#
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
#

import unittest
import hashlib
import io
import random
import tempfile
import os
from sevsnpmeasure.sev_hashes import SevHashes


class TestSevHashes(unittest.TestCase):
    def test_calc_hash_digest_random(self):
        random.seed(42)
        # Generate 128kb of random data
        data = bytes([random.randint(0, 255) for _ in range(128 * 1024)])

        expected_hash = hashlib.sha256(data).digest()
        actual_hash = SevHashes.calc_hash_digest(io.BytesIO(data))

        self.assertEqual(actual_hash, expected_hash)

    def test_calc_hash_digest_empty(self):
        data = b""
        expected_hash = hashlib.sha256(data).digest()
        actual_hash = SevHashes.calc_hash_digest(io.BytesIO(data))

        self.assertEqual(actual_hash, expected_hash)

    def test_calc_initrd_hash_digest_empty(self):
        expected_hash = hashlib.sha256(b"").digest()
        actual_hash = SevHashes.calc_initrd_hash_digest("")
        self.assertEqual(actual_hash, expected_hash)

    def test_calc_initrd_hash_digest_with_file(self):
        random.seed(43)
        data = bytes([random.randint(0, 255) for _ in range(1024)])
        expected_hash = hashlib.sha256(data).digest()

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            actual_hash = SevHashes.calc_initrd_hash_digest(tmp_path)
            self.assertEqual(actual_hash, expected_hash)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
