#
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
#

import unittest
import base64
from sevsnpmeasure import id_block

# Generate test id_key
# openssl ecparam -name secp384r1 -genkey -noout -out keyfile/id_key_test.pem

# Generate test author_key
# openssl ecparam -name secp384r1 -genkey -noout -out keyfile/author_key_test.pem


class TestIdBlock(unittest.TestCase):
    def test_id_block(self):
        ld = base64.b64decode("B28FLQi9p6cAqipgjFyqawDrrSl7bWioWkWx5mmlWLZ+G5HShKMB/mPE+gdQRn7t")
        block = id_block.snp_calc_id_block(
            ld,
            bytes(16),
            bytes(16),
            0,
            "tests/keyfile/id_key_test.pem",
            "tests/keyfile/author_key_test.pem"
        )
        self.assertEqual(
            base64.b64decode('B28FLQi9p6cAqipgjFyqawDrrSl7bWioWkWx5mmlWLZ+G5HShKMB/mPE+gdQRn7t'
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAgAAAAAA'),
            block["id_block"]
        )
        self.assertEqual(
            base64.b64decode("hwt+NcU/inLQ0yL3WrKvgmJ5Kq9leWIs5BMcPyHyied8sFYKXjuQs5MuZ07HCcsU"),
            block["id_key_digest"]
        )
        self.assertEqual(
            base64.b64decode("YxEcNLv8Ckk4+aAJvQdJgNgXIyPmFZnJ/TNtqGcySOHcqY0L6PdjdqEGuK/UwKBX"),
            block["author_key_digest"]
        )
