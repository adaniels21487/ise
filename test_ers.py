import unittest
import os
from cream import ERS


class ErsTest(unittest.TestCase):
    def setUp(self):
        self.ise = ERS(
            os.environ.get("ERS_URI", "https://10.0.0.1:9060"),
            os.environ.get("ERS_USERNAME", False),
            os.environ.get("ERS_PASSWORD", False),
        )

    def tearDown(self):
        self.ise.close()

    def test_mac_test(self):
        result = self.ise._mac_test("24:be:05:0b:01:ab")
        self.assertTrue(result)

    def test_get_endpointgroup_by_name(self):
        data = self.ise.get_endpoint_group(group="Blacklist")
        self.assertTrue(len(data) > 0)

    def test_get_endpointgroup_by_id(self):
        data = self.ise.get_endpoint_group(pk="aa000c30-8bff-11e6-996c-525400b48521")
        self.assertTrue(len(data) > 0)


if __name__ == "__main__":
    unittest.main()
