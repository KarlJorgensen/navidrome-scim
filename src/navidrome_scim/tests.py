
import tempfile
import unittest

import navidrome_scim

class TestCase(unittest.TestCase):
    def setUp(self):
        """Prepare the test"""
        super().setUp()
        self.__tmpdir = tempfile.TemporaryDirectory()
        self.app = navidrome_scim.create_app(instance_path=self.__tmpdir.name)
        self.app.config['TESTING'] = True
        self.app.testing = True

    def tearDown(self):
        """Cleanup after the test"""
        if self.__tmpdir:
            self.__tmpdir.cleanup()
            self.__tmpdir = None
        super().tearDown()

class TestProviderInfo(TestCase):

    def test_basic(self):
        """Getting the provider info must work"""
        res = self.client.get('/scim/v2/ServiceProviderInfo')
        assert res.status_code == 200

if __name__ == '__main__':
    unittest.main()
