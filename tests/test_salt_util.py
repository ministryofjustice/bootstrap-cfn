import unittest
import mock
from bootstrap_cfn import errors
import os
import sys
#This is a hack so that we don't need salt to run our tests
sys.modules['salt'] = mock.Mock()
sys.modules['salt.runner'] = mock.Mock()
sys.modules['salt.client'] = mock.Mock()
import salt
from bootstrap_cfn import salt_utils

class SaltUtilTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def test_state_result(self):
        salt.config = mock.Mock()
        mock_result = mock.Mock()
        mock_config = {'cmd.return_value': {'minon1': {'state':{'result':True}}}}
        mock_result.configure_mock(**mock_config)

        mock_client = mock.Mock()
        mock_client.return_value = mock_result

        mock_runner = mock.Mock(RunnerClient=mock_client)

        salt.runner = mock_runner
        x = salt_utils.state_result('12345')
        self.assertTrue(x)

    def test_no_state_result(self):
        salt.config = mock.Mock()
        mock_result = mock.Mock()
        mock_config = {'cmd.return_value': {}}
        mock_result.configure_mock(**mock_config)

        mock_client = mock.Mock()
        mock_client.return_value = mock_result

        mock_runner = mock.Mock(RunnerClient=mock_client)

        salt.runner = mock_runner
        x = salt_utils.state_result('12345')
        self.assertFalse(x)

    def test_check_state_result_good(self):
        result = {'minon1': {'state':{'result':True}},
                  'minion2': {'state':{'result':True}}} 
        x = salt_utils.check_state_result(result)
        self.assertTrue(x)

    def test_check_state_result_bad(self):
        result = {'minon1': {'state':{'result':False}},
                  'minion2': {'state':{'result':True}}} 
        with self.assertRaises(errors.SaltStateError):
            salt_utils.check_state_result(result)

    def test_check_state_result_parse_error(self):
        result = {'minon1': ['SOME SALT PARSER ERROR']}
        with self.assertRaises(errors.SaltParserError):
            salt_utils.check_state_result(result)

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
