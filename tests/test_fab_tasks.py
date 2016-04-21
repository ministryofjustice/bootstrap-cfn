import unittest

from bootstrap_cfn import fab_tasks  # noqa
from mock import patch, Mock  # noqa

fake_profile = {'lol': {'aws_access_key_id': 'secretz', 'aws_secret_access_key': 'verysecretz'}}


class TestFabTasks(unittest.TestCase):

    def test_loaded(self):
        # Not a great test, but it at least checks for syntax erros in the file
        pass

    @patch('botocore.session.Session.get_scoped_config')
    def test_aws_task(self, mock_botocore):
        mock_botocore.return_value = fake_profile['lol']
        fab_tasks.aws('nonexistent_profile')
