import os
import tempfile
import unittest

import boto.cloudformation
import boto.ec2.autoscale

import mock

import yaml

from bootstrap_cfn import cloudformation, errors, iam


class CfnTestCase(unittest.TestCase):

    def setUp(self):
        self.work_dir = tempfile.mkdtemp()

        self.env = mock.Mock()
        self.env.aws = 'dev'
        self.env.aws_profile = 'the-profile-name'
        self.env.environment = 'dev'
        self.env.application = 'unittest-app'
        self.env.config = os.path.join(self.work_dir, 'test_config.yaml')

        config = {'dev': {'ec2': {'auto_scaling': {'desired': 1, 'max': 3,
                                                   'min': 0},
                                  'block_devices': [{'DeviceName': '/dev/sda1',
                                                     'VolumeSize': 10},
                                                    {'DeviceName': '/dev/sdf',
                                                     'VolumeSize': 10}],
                                  'parameters': {'InstanceType': 't2.micro',
                                                 'KeyName': 'default'},
                                  'security_groups': [{'CidrIp': '0.0.0.0/0',
                                                       'FromPort': 22,
                                                       'IpProtocol': 'tcp',
                                                       'ToPort': 22},
                                                      {'CidrIp': '0.0.0.0/0',
                                                       'FromPort': 80,
                                                       'IpProtocol': 'tcp',
                                                       'ToPort': 80}],
                                  'tags': {'Apps': 'test', 'Env': 'dev',
                                           'Role': 'docker'}},
                          'elb': [{'hosted_zone': 'kyrtest.pf.dsd.io.',
                                   'listeners': [{'InstancePort': 80,
                                                  'LoadBalancerPort': 80,
                                                  'Protocol': 'TCP'},
                                                 {'InstancePort': 443,
                                                  'LoadBalancerPort': 443,
                                                  'Protocol': 'TCP',
                                                  'PolicyNames': 'PinDownSSLNegotiationPolicy201505'}],
                                   'name': 'test-dev-external',
                                   'scheme': 'internet-facing'},
                                  {'hosted_zone': 'kyrtest.pf.dsd.io.',
                                   'listeners': [{'InstancePort': 80,
                                                  'LoadBalancerPort': 80,
                                                  'Protocol': 'TCP'}],
                                   'name': 'test-dev-internal',
                                   'scheme': 'internet-facing'}],
                          'rds': {'backup-retention-period': 1,
                                  'db-engine': 'postgres',
                                  'db-engine-version': '9.3.5',
                                  'db-master-password': 'testpassword',
                                  'db-master-username': 'testuser',
                                  'db-name': 'test',
                                  'instance-class': 'db.t2.micro',
                                  'multi-az': False,
                                  'storage': 5,
                                  'storage-type': 'gp2'},
                          's3': {'static-bucket-name': 'moj-test-dev-static'}}}
        yaml.dump(config, open(self.env.config, 'w'))

        self.stack_name = '{0}-{1}'.format(self.env.application,
                                           self.env.environment)
        self.cf = cloudformation.Cloudformation(self.env.aws_profile, 'aws_region')

    def test_cf_create(self):
        cf_mock = mock.Mock()
        cf_connect_result = mock.Mock(name='cf_connect')
        cf_mock.return_value = cf_connect_result
        mock_config = {'create_stack.return_value': self.stack_name}
        cf_connect_result.configure_mock(**mock_config)
        boto.cloudformation.connect_to_region = cf_mock
        test_tags = {'Env': 'Dev', 'MiscTag': 'misc'}
        cf = cloudformation.Cloudformation(self.env.aws_profile)
        x = cf.create(self.stack_name, '{}', test_tags)

        # Check we called create with the right values
        cf_connect_result.create_stack.assert_called_once_with(
            template_body='{}',
            stack_name=self.stack_name,
            capabilities=['CAPABILITY_IAM'],
            tags=test_tags)
        self.assertEqual(x, self.stack_name)

    def test_cf_delete(self):
        cf_mock = mock.Mock()
        cf_connect_result = mock.Mock(name='cf_connect')
        cf_mock.return_value = cf_connect_result
        example_return = {'DeleteStackResponse': {'ResponseMetadata': {'RequestId': 'someuuid'}}}
        mock_config = {'delete_stack.return_value': example_return}
        cf_connect_result.configure_mock(**mock_config)
        boto.cloudformation.connect_to_region = cf_mock
        cf = cloudformation.Cloudformation(self.env.aws_profile)
        x = cf.delete(self.stack_name)
        self.assertTrue('DeleteStackResponse' in x.keys())

    def test_wait_for_stack_missing(self):
        stack_mock = mock.Mock(stack_name='my-stack-name')

        cf_mock = mock.Mock()
        cf_connect_result = mock.Mock(name='cf_connect')
        cf_mock.return_value = cf_connect_result
        mock_config = {'describe_stacks.return_value': [stack_mock]}
        cf_connect_result.configure_mock(**mock_config)
        boto.cloudformation.connect_to_region = cf_mock
        cf = cloudformation.Cloudformation(self.env.aws_profile)
        x = cf.stack_missing('not-a-stack-name')
        self.assertTrue(x)

    def test_wait_for_stack_not_missing(self):
        stack_mock = mock.Mock(stack_name='my-stack-name')

        cf_mock = mock.Mock()
        cf_connect_result = mock.Mock(name='cf_connect')
        cf_mock.return_value = cf_connect_result
        mock_config = {'describe_stacks.return_value': [stack_mock]}
        cf_connect_result.configure_mock(**mock_config)
        boto.cloudformation.connect_to_region = cf_mock
        cf = cloudformation.Cloudformation(self.env.aws_profile)
        with self.assertRaises(errors.CfnTimeoutError):
            cf.wait_for_stack_missing('my-stack-name', 1, 1)

    def test_stack_missing(self):
        stack_mock = mock.Mock(stack_name='my-stack-name')

        cf_mock = mock.Mock()
        cf_connect_result = mock.Mock(name='cf_connect')
        cf_mock.return_value = cf_connect_result
        mock_config = {'describe_stacks.return_value': [stack_mock]}
        cf_connect_result.configure_mock(**mock_config)
        boto.cloudformation.connect_to_region = cf_mock
        cf = cloudformation.Cloudformation(self.env.aws_profile)
        x = cf.stack_missing('not-a-stack-name')
        self.assertTrue(x)

    def test_stack_not_missing(self):
        stack_mock = mock.Mock(stack_name='my-stack-name')

        cf_mock = mock.Mock()
        cf_connect_result = mock.Mock(name='cf_connect')
        cf_mock.return_value = cf_connect_result
        mock_config = {'describe_stacks.return_value': [stack_mock]}
        cf_connect_result.configure_mock(**mock_config)
        boto.cloudformation.connect_to_region = cf_mock
        cf = cloudformation.Cloudformation(self.env.aws_profile)
        x = cf.stack_missing('my-stack-name')
        self.assertFalse(x)

    def test_stack_wait_for_stack_not_done(self):
        stack_evt_mock = mock.Mock()
        rt = mock.PropertyMock(return_value='AWS::CloudFormation::Stack')
        rs = mock.PropertyMock(return_value='CREATE_COMPLETE_LOL')
        type(stack_evt_mock).resource_type = rt
        type(stack_evt_mock).resource_status = rs
        mock_config = {'describe_stack_events.return_value': [stack_evt_mock]}

        cf_mock = mock.Mock()
        cf_connect_result = mock.Mock(name='cf_connect')
        cf_mock.return_value = cf_connect_result
        cf_connect_result.configure_mock(**mock_config)

        boto.cloudformation.connect_to_region = cf_mock

        with self.assertRaises(errors.CfnTimeoutError):
            print cloudformation.Cloudformation(
                self.env.aws_profile).wait_for_stack_done(self.stack_name, 1, 1)
        
    def test_wait_for_stack_done(self):
        stack_evt_mock = mock.Mock()
        rt = mock.PropertyMock(return_value='AWS::CloudFormation::Stack')
        rs = mock.PropertyMock(return_value='CREATE_COMPLETE')
        type(stack_evt_mock).resource_type = rt
        type(stack_evt_mock).resource_status = rs
        mock_config = {'describe_stack_events.return_value': [stack_evt_mock]}

        cf_mock = mock.Mock()
        cf_connect_result = mock.Mock(name='cf_connect')
        cf_mock.return_value = cf_connect_result
        cf_connect_result.configure_mock(**mock_config)

        boto.cloudformation.connect_to_region = cf_mock

        self.assertTrue(cloudformation.Cloudformation(
            self.env.aws_profile).wait_for_stack_done(self.stack_name, 1, 1))

    def test_stack_done(self):
        stack_evt_mock = mock.Mock()
        rt = mock.PropertyMock(return_value='AWS::CloudFormation::Stack')
        rs = mock.PropertyMock(return_value='CREATE_COMPLETE')
        type(stack_evt_mock).resource_type = rt
        type(stack_evt_mock).resource_status = rs
        mock_config = {'describe_stack_events.return_value': [stack_evt_mock]}

        cf_mock = mock.Mock()
        cf_connect_result = mock.Mock(name='cf_connect')
        cf_mock.return_value = cf_connect_result
        cf_connect_result.configure_mock(**mock_config)

        boto.cloudformation.connect_to_region = cf_mock

        self.assertTrue(cloudformation.Cloudformation(
            self.env.aws_profile).stack_done(self.stack_name))

    def test_stack_not_done(self):
        stack_evt_mock = mock.Mock()
        rt = mock.PropertyMock(return_value='AWS::CloudFormation::Stack')
        rs = mock.PropertyMock(return_value='CREATE_COMPLETE_FAKE')
        type(stack_evt_mock).resource_type = rt
        type(stack_evt_mock).resource_status = rs

        cf_mock = mock.Mock()
        cf_connect_result = mock.Mock(name='cf_connect')
        cf_mock.return_value = cf_connect_result
        mock_config = {'describe_stack_events.return_value': [stack_evt_mock]}
        cf_connect_result.configure_mock(**mock_config)
        boto.cloudformation.connect_to_region = cf_mock

        self.assertFalse(cloudformation.Cloudformation(
            self.env.aws_profile).stack_done(self.stack_name))

    def test_ssl_upload(self):
        iam_mock = mock.Mock()
        iam_connect_result = mock.Mock(name='iam_connect')
        iam_mock.return_value = iam_connect_result
        boto.iam.connect_to_region = iam_mock
        i = iam.IAM(self.env.aws_profile)
        x = i.upload_ssl_certificate({}, self.stack_name)
        self.assertTrue(x)

    def test_ssl_delete(self):
        iam_mock = mock.Mock()
        iam_connect_result = mock.Mock(name='iam_connect')
        iam_mock.return_value = iam_connect_result
        boto.iam.connect_to_region = iam_mock
        i = iam.IAM(self.env.aws_profile)
        x = i.delete_ssl_certificate({}, self.stack_name)
        self.assertTrue(x)

if __name__ == '__main__':
    unittest.main()
