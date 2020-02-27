from .cream import ERS
import unittest


class ErsTest(unittest.TestCase):
    def setUp(self):
        self.ise = ERS("ise_node", "ers_user", "ers_pass")

    def test_mac_test(self):
        result = self.ise._mac_test("24:be:05:0b:01:ab")

        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
