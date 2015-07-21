import os
import tempfile
import unittest

import boto.ec2.autoscale
from boto.ec2.autoscale.group import AutoScalingGroup

import mock

from bootstrap_cfn import autoscale


def get_all_groups(names=None, max_records=None, next_token=None):

    groups = []

    for i in xrange(1, 3):
        tags = [
            boto.ec2.autoscale.tag.Tag(
                None,
                key='aws:cloudformation:stack-name',
                value='test{0}'.format(i))
        ]

        asg = AutoScalingGroup()
        asg.name = 'test{0}'.format(i)
        asg.tags = tags
        groups.append(asg)

    return groups


class TestAutoscale(unittest.TestCase):

    def setUp(self):
        self.work_dir = tempfile.mkdtemp()
        self.env = mock.Mock()
        self.env.aws = 'dev'
        self.env.environment = 'dev'
        self.env.application = 'unittest-app'
        self.env.config = os.path.join(self.work_dir, 'test_config.yaml')

    def test_loaded(self):
        pass

    def test_set_autoscaling_group(self):
        with mock.patch('boto.ec2.autoscale.connect_to_region') as conn:

            conn.return_value.get_all_groups = get_all_groups

            # Test successfully found stack
            a = autoscale.Autoscale(self.env.aws_profile)
            a.set_autoscaling_group('test1')
            self.assertEquals(a.group.name, 'test1')

            # Test no found stack
            a = autoscale.Autoscale(self.env.aws_profile)
            a.set_autoscaling_group('test')
            self.assertIsNone(a.group)

    def test_set_tag(self):
        with mock.patch('boto.ec2.autoscale.connect_to_region') as conn:
            conn.return_value.get_all_groups = get_all_groups
            # Test if no stack found, don't continue
            a = autoscale.Autoscale(self.env.aws_profile)
            self.assertIsNone(a.set_tag('test_key', 'test_value'))
