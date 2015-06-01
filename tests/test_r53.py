from bootstrap_cfn import r53
import unittest
import tempfile
import boto.route53
import mock
import os


class BootstrapCfnR53TestCase(unittest.TestCase):

    def setUp(self):
        self.work_dir = tempfile.mkdtemp()
        self.env = mock.Mock()
        self.env.aws = 'dev'
        self.env.aws_profile = 'the-profile-name'
        self.env.environment = 'dev'
        self.env.application = 'unittest-app'
        self.env.config = os.path.join(self.work_dir, 'test_config.yaml')

    def test_update_dns_record(self):
        r53_mock = mock.Mock()
        r53_connect_result = mock.Mock(name='cf_connect')
        r53_mock.return_value = r53_connect_result
        boto.route53.connect_to_region = r53_mock
        r = r53.R53(self.env.aws_profile)
        x = r.update_dns_record('blah/blah', 'x.y', 'A', '1.1.1.1')
        self.assertTrue(x)

    def test_get_hosted_zone_id(self):
        r53_mock = mock.Mock()
        r53_connect_result = mock.Mock(name='cf_connect')
        r53_mock.return_value = r53_connect_result
        response = {'GetHostedZoneResponse': {}}
        zone_response = {'HostedZone': {'Id': 'blah/blah'}}
        response['GetHostedZoneResponse'] = zone_response

        mock_config = {'get_hosted_zone_by_name.return_value': response}
        r53_connect_result.configure_mock(**mock_config)
        boto.route53.connect_to_region = r53_mock
        r = r53.R53(self.env.aws_profile)
        x = r.get_hosted_zone_id('blah')
        self.assertEquals(x, 'blah/blah')

    def test_get_record(self):
        r53_mock = mock.Mock()
        r53_connect_result = mock.Mock(name='cf_connect')
        r53_mock.return_value = r53_connect_result
        m = mock.Mock(resource_records=['1.1.1.1'])
        m.name = 'blah.dsd.io.'
        m.type = 'A'
        response = [m]

        mock_config = {'get_all_rrsets.return_value': response}
        r53_connect_result.configure_mock(**mock_config)
        boto.route53.connect_to_region = r53_mock
        r = r53.R53(self.env.aws_profile)
        x = r.get_record('dsd.io', 'ASDAKSLDK', 'blah', 'A')
        self.assertEquals(x, '1.1.1.1')

    def test_get_TXT_record(self):
        r53_mock = mock.Mock()
        r53_connect_result = mock.Mock(name='cf_connect')
        r53_mock.return_value = r53_connect_result
        m = mock.Mock(resource_records=['"lollol"'])
        m.name = 'blah.dsd.io.'
        m.type = 'TXT'
        response = [m]

        mock_config = {'get_all_rrsets.return_value': response}
        r53_connect_result.configure_mock(**mock_config)
        boto.route53.connect_to_region = r53_mock
        r = r53.R53(self.env.aws_profile)
        x = r.get_record('dsd.io', 'ASDAKSLDK', 'blah', 'TXT')
        self.assertEquals(x, 'lollol')
