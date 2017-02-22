import re
import unittest

import boto

import yaml


from bootstrap_cfn import cloudformation, config, fab_tasks, iam, r53
from mock import patch, Mock  # noqa


fake_profile = {'lol': {'aws_access_key_id': 'secretz', 'aws_secret_access_key': 'verysecretz'}}


def set_up_basic_config():
    '''
    Returns: a config.yaml test example

    '''
    basic_config = {'master_zone': 'dsd.io',
                    'ec2': {},
                    'elb': [{'hosted_zone': 'unittest.dsd.io.',
                             'name': 'unittest',
                             'scheme': 'internet-facing'}],
                    'rds': {},
                    's3': {},
                    'ssl': {'dsd.io': {'cert': ('-----BEGIN CERTIFICATE-----'
                                                'CHAIN2CHAIN2CHAIN2CHAIN2CHA'
                                                '-----END CERTIFICATE-----'),
                                       'key': ('-----BEGIN CERTIFICATE-----'
                                               'CHAIN2CHAIN2CHAIN2CHAIN2CHA'
                                               '-----END CERTIFICATE-----')
                                       }
                            }
                    }
    return yaml.dump(basic_config)


class TestFabTasks(unittest.TestCase):

    def test_loaded(self):
        # Not a great test, but it at least checks for syntax erros in the file
        pass

    def cfn_mock(self):
        cf_mock = Mock()
        cf_connect_result = Mock(name='cf_connect')
        cf_mock.return_value = cf_connect_result
        stack = "cfn_mock-dev-12345678"
        example_return = {'DeleteStackResponse': {'ResponseMetadata': {'RequestId': 'someuuid'}}}
        stack_mock = Mock(stack_name=stack)
        stack_mock.resource_status = 'CREATE_COMPLETE'
        mock_config = {'delete_stack.return_value': example_return,
                       'create_stack.return_value': stack,
                       'describe_stacks.return_value': [stack_mock],
                       'stack_done.return_value': True,
                       'describe_stack_events.return_value': [stack_mock]}
        cf_connect_result.configure_mock(**mock_config)
        boto.cloudformation.connect_to_region = cf_mock
        cf = cloudformation.Cloudformation("profile_name")
        return cf

    def iam_mock(self):
        iam_mock = Mock()
        iam_connect_result = Mock(name='iam_connect')
        iam_mock.return_value = iam_connect_result
        mock_config = {'delete_ssl_certificate.return_value': True}
        iam_connect_result.configure_mock(**mock_config)
        boto.iam.connect_to_region = iam_mock
        i = iam.IAM("profile_name")
        return i

    def r53_mock(self):
        '''
        Mock route53 connection and dsn records
        Returns:
            R53 Mock object
        '''
        r53_mock = Mock()
        r53_connect_result = Mock(name='r53_connect')
        r53_mock.return_value = r53_connect_result
        m1 = Mock(alias_dns_name="unittest1")
        m1.name = 'unittest_elb-12345678.dsd.io.'
        m1.type = 'A'
        m1.alias_hosted_zone_id = "ASDAKSLSA"
        m1.alias_evaluate_target_health = False
        m2 = Mock(resource_records=['"12345678"'])
        m2.name = 'stack.active.unittest-dev.dsd.io.'
        m2.type = 'TXT'
        m2.alias_hosted_zone_id = "ASDAKSLSA"
        m2.alias_evaluate_target_health = False
        m3 = Mock(alias_dns_name="unittest1")
        m3.name = 'unittest_elb.dsd.io.'
        m3.type = 'A'
        m3.alias_hosted_zone_id = "ASDAKSLSA"
        m3.alias_evaluate_target_health = False
        m4 = Mock(resource_records=['"12345678"'])
        m4.name = 'stack.test.unittest-dev.dsd.io.'
        m4.type = 'TXT'
        m4.alias_hosted_zone_id = "ASDAKSLSA"
        m4.alias_evaluate_target_health = False
        m5 = Mock(resource_records=['"12345678"'])
        m5.name = 'deployarn.test.unittest-dev.dsd.io.'
        m5.type = 'TXT'
        m5.alias_hosted_zone_id = "ASDAKSLSA"
        m5.alias_evaluate_target_health = False
        response = [m1, m2, m3, m4, m5]
        mock_config = {'update_dns_record.return_value': True,
                       'get_all_rrsets.return_value': response,
                       'delete_dns_record.return_value': True}
        r53_connect_result.configure_mock(**mock_config)
        boto.route53.connect_to_region = r53_mock
        r = r53.R53("profile_name")
        return r

    def connection_side_effect(self, klass):
        '''
        Returns r53/cfn/iam mock for get_connection(klass)
        depending on different klass
        '''
        if klass.__name__ == r53.R53.__name__:
            return self.r53_mock()
        elif klass.__name__ == cloudformation.Cloudformation.__name__:
            return self.cfn_mock()
        elif klass.__name__ == iam.IAM.__name__:
            return self.iam_mock()

    @patch('botocore.session.Session.get_scoped_config')
    def test_aws_task(self, mock_botocore):
        mock_botocore.return_value = fake_profile['lol']
        fab_tasks.aws('nonexistent_profile')

    @patch('bootstrap_cfn.fab_tasks.get_config')
    def test_get_all_elbs(self, get_config_function):
        '''
        Check if get_all_elbs() returns all internet facing elbs.
        Args:
            get_config_function: mock of get_config() function

        '''
        basic_config_mock = yaml.load(set_up_basic_config())
        get_config_function.return_value = config.ConfigParser(
            basic_config_mock, "unittest_stack_name", "dev", "test")

        all_elbs = fab_tasks.get_all_elbs()
        self.assertEqual(all_elbs, ["unittest"])

    @patch('bootstrap_cfn.fab_tasks.get_config')
    def test_get_all_elbs_with_filter(self, get_config_function):
        '''
        Check if get_all_elbs() returns correct Internet facing ELB,
        given a filter that would should match only a specific name.
        Args:
            get_config_function: mock of get_config() function

        '''
        basic_config_mock = yaml.load(set_up_basic_config())
        basic_config_mock['elb'].append({'hosted_zone': 'unittest.dsd.io.',
                                         'name': 'unittest2',
                                         'scheme': 'internet-facing'})

        get_config_function.return_value = config.ConfigParser(
            basic_config_mock, "unittest_stack_name", "dev", "test")

        regex = re.compile('unittest2')
        filtered_elbs = fab_tasks.get_all_elbs(regex.match)
        self.assertEqual(filtered_elbs, ["unittest2"])

    @patch('bootstrap_cfn.fab_tasks.get_public_elbs', return_value=["unittest_elb"])
    def test_get_first_public_elb(self, get_all_elbs_function):
        '''
        Check if get_first_public_elb() returns the first internet facing elb
        Args:
            get_all_elbs_function: mock of get_all_elbs(), a list of elbs

        '''
        first_elb = fab_tasks.get_first_public_elb()
        self.assertEqual(first_elb, "unittest_elb")

    @patch('bootstrap_cfn.fab_tasks.get_connection')
    @patch('bootstrap_cfn.fab_tasks.get_zone_name', return_value="dsd.io")
    @patch('bootstrap_cfn.fab_tasks.get_legacy_name', return_value="unittest-dev")
    @patch('bootstrap_cfn.fab_tasks.get_zone_id', return_value="ASDAKSLDK")
    @patch('bootstrap_cfn.fab_tasks.get_all_elbs', return_value=["unittest_elb"])
    def test_get_active_stack(self, get_public_elbs_function,
                              get_zone_id_function,
                              get_legacy_name_function,
                              get_zone_name_function,
                              get_connection_function):
        '''
        Return stack_id of m2 record defined in def r53_mock()
        Args:
            get_public_elbs_function:
            get_zone_id_function:
            get_legacy_name_function:
            get_zone_name_function:
            get_connection_function:

        Returns:

        '''
        get_connection_function.side_effect = self.connection_side_effect
        # fab_tasks.get_connection = Mock(return_value=r)

        res = fab_tasks.get_active_stack()
        self.assertTrue(res)
        self.assertEqual(res, "12345678")

    @patch('bootstrap_cfn.fab_tasks.arn_record_name')
    @patch('bootstrap_cfn.fab_tasks.get_connection')
    @patch('bootstrap_cfn.fab_tasks.get_zone_name', return_value="dsd.io")
    @patch('bootstrap_cfn.fab_tasks.get_legacy_name', return_value="unittest-dev")
    @patch('bootstrap_cfn.fab_tasks.get_zone_id', return_value="ASDAKSLDK")
    @patch('bootstrap_cfn.fab_tasks.get_all_elbs', return_value=["unittest_elb"])
    @patch('bootstrap_cfn.fab_tasks.get_first_public_elb', return_value="unittest_elb")
    def test_set_active_stack(self, get_public_elbs_function,
                              get_first_public_elb_function,
                              get_zone_id_function,
                              get_legacy_name_function,
                              get_zone_name_function,
                              get_connection_function,
                              arn_record_name_mock):
        '''
        set stack tagged with "test" as active stack,
        using m4 record defined in def r53_mock()
        Args:
            get_public_elbs_function:
            get_first_public_elb_function:
            get_zone_id_function:
            get_legacy_name_function:
            get_zone_name_function:
            get_connection_function:
            arn_record_name: set up deployarn record name, e.g. deployarn.tag.app-env.dsd.io
        Returns:

        '''
        arn_record_name_mock.side_effect = self.arn_record_name_side_effect
        get_connection_function.side_effect = self.connection_side_effect
        # fab_tasks.get_connection = Mock(return_value=r)
        ret = fab_tasks.set_active_stack("test", force=True)
        self.assertTrue(ret)

    def arn_record_name_side_effect(self, stack_tag, zone_name):
        return 'deployarn.{}.unittest-dev.dsd.io.'.format(stack_tag)

    @patch('bootstrap_cfn.fab_tasks.isactive', return_value=True)
    @patch('bootstrap_cfn.fab_tasks.get_connection')
    @patch('bootstrap_cfn.fab_tasks.get_config')
    @patch('bootstrap_cfn.fab_tasks.get_zone_name', return_value="dsd.io")
    @patch('bootstrap_cfn.fab_tasks.get_legacy_name', return_value="unittest-dev")
    @patch('bootstrap_cfn.fab_tasks.get_zone_id', return_value="ASDAKSLDK")
    @patch('bootstrap_cfn.fab_tasks.get_first_public_elb', return_value="unittest_elb")
    @patch('bootstrap_cfn.fab_tasks.get_stack_name', return_value="unittest-dev-12345678")
    def test_cfn_delete_active_records(self, get_stack_name_function,
                                       get_first_public_elb_function,
                                       get_zone_id_function,
                                       get_legacy_name_function,
                                       get_zone_name_function,
                                       get_config_function,
                                       get_connection_function,
                                       isactive_function):
        '''
        Delete active dns records
        Do not delete stack
        Args:
            get_stack_name_function:
            get_first_public_elb_function:
            get_zone_id_function:
            get_legacy_name_function:
            get_zone_name_function:
            get_config_function:
            get_connection_function:
            isactive_function: to mock env.tag to be active

        Returns:

        '''
        get_connection_function.side_effect = self.connection_side_effect
        basic_config_mock = yaml.load(set_up_basic_config())
        get_config_function.return_value = config.ConfigParser(
            basic_config_mock, "unittest_stack_name", "dev", "test")
        ret = fab_tasks.cfn_delete(force=True)
        self.assertTrue(ret)

    @patch('bootstrap_cfn.fab_tasks.get_env_tag', return_value='test')
    @patch('bootstrap_cfn.fab_tasks.isactive', return_value=False)
    @patch('bootstrap_cfn.fab_tasks.get_connection')
    @patch('bootstrap_cfn.fab_tasks.get_config')
    @patch('bootstrap_cfn.fab_tasks.get_zone_name', return_value="dsd.io")
    @patch('bootstrap_cfn.fab_tasks.get_legacy_name', return_value="unittest-dev")
    @patch('bootstrap_cfn.fab_tasks.get_zone_id', return_value="ASDAKSLDK")
    @patch('bootstrap_cfn.fab_tasks.get_first_public_elb', return_value="unittest_elb")
    @patch('bootstrap_cfn.fab_tasks.get_stack_name', return_value="unittest-dev-12345678")
    def test_cfn_delete_inactive_stack(self, get_stack_name_function,
                                       get_first_public_elb_function,
                                       get_zone_id_function,
                                       get_legacy_name_function,
                                       get_zone_name_function,
                                       get_config_function,
                                       get_connection_function,
                                       isactive_function,
                                       get_env_tag_function):
        '''
        if tag is "active", delete only active dns records(TXT and Alias)
        NB this method didn't test ssl deleting
        Args:
            get_stack_name_function:
            get_first_public_elb_function:
            get_zone_id_function:
            get_legacy_name_function:
            get_zone_name_function:
            get_config_function:
            get_connection_function:
            isactive_function: mock env.tag to be inactive
            get_env_tag_function: mock to get env.tag

        Returns:

        '''
        get_connection_function.side_effect = self.connection_side_effect
        basic_config_mock = yaml.load(set_up_basic_config())
        get_config_function.return_value = config.ConfigParser(
            basic_config_mock, "unittest_stack_name", "dev", "test")
        # tail_function.side_effect = self.tail_logs
        ret = fab_tasks.cfn_delete(force=True)
        self.assertTrue(ret)

    def tail_logs(self, stack, stack_name):
        print "{}.{} logs".format(stack, stack_name)
        return True

    @patch('bootstrap_cfn.fab_tasks._validate_fabric_env')
    @patch('bootstrap_cfn.utils.get_events', return_value=[])
    @patch('bootstrap_cfn.config.ConfigParser.process', return_value="test")
    @patch('bootstrap_cfn.fab_tasks.get_cloudformation_tags', return_value="test")
    @patch('bootstrap_cfn.fab_tasks.get_connection')
    @patch('bootstrap_cfn.fab_tasks.get_config')
    @patch('bootstrap_cfn.fab_tasks.get_zone_name', return_value="dsd.io")
    @patch('bootstrap_cfn.fab_tasks.get_legacy_name', return_value="unittest-test")
    @patch('bootstrap_cfn.fab_tasks.get_zone_id', return_value="ASDAKSLDK")
    @patch('bootstrap_cfn.fab_tasks.get_first_public_elb', return_value="unittest_elb")
    @patch('bootstrap_cfn.fab_tasks.get_stack_name', return_value="unittest-test-12345678")
    def test_cfn_create_without_ssl(self, get_stack_name_function,
                                    get_first_public_elb_function,
                                    get_zone_id_function,
                                    get_legacy_name_function,
                                    get_zone_name_function,
                                    get_config_function,
                                    get_connection_function,
                                    get_cloudformation_tags_function,
                                    process_function,
                                    get_events_function,
                                    _validate_fabric_env_function):
        '''
        create a stack without uploading ssl
        Note: when testing creating stack, get_stack_name.return_value
         should be different from stack_name inside cfn_mock()
         so that Cloudformation.stack_missing() in utils.tail() will be True
        Args:
            get_stack_name_function:
            get_first_public_elb_function:
            get_zone_id_function:
            get_legacy_name_function:
            get_zone_name_function:
            get_config_function:
            get_connection_function: to mock get_connection(klass)
            get_cloudformation_tags_function: to mock cfn.create() whose arguments include it
            process_function: to mock cfn.create() whose arguments include ConfigParser.process
            get_events_function: this is to mock utils.tail() which includes get_events()

        Returns:

        '''
        # this does not mock fabric env value actually.
        # I just mock the whole function to do nothing for test simplicity.
        _validate_fabric_env_function.side_effect = {"env.keyname.return_value": "default"}

        get_connection_function.side_effect = self.connection_side_effect
        basic_config_mock = yaml.load(set_up_basic_config())
        get_config_function.return_value = config.ConfigParser(
            basic_config_mock, "unittest_stack_name", "dev", "test", "default")
        ret = fab_tasks.cfn_create(False)
        self.assertTrue(ret)

    @patch('bootstrap_cfn.fab_tasks.get_legacy_name', return_value="unittest-dev")
    def test_get_tag_record_name(self, get_legacy_name_function):
        '''
        Check if it returns tagged record name
        Args:
            get_legacy_name_function: mock of get_legacy_name,
            "[application]-[environment]"

        Returns:

        '''
        record_name = fab_tasks.get_tag_record_name("test")
        self.assertEqual(record_name, "stack.test.unittest-dev")

    @patch('bootstrap_cfn.fab_tasks.get_connection')
    @patch('bootstrap_cfn.fab_tasks.get_zone_name', return_value="dsd.io")
    @patch('bootstrap_cfn.fab_tasks.get_legacy_name', return_value="unittest-dev")
    @patch('bootstrap_cfn.fab_tasks.get_zone_id', return_value="ASDAKSLDK")
    @patch('bootstrap_cfn.fab_tasks.get_first_public_elb', return_value="unittest_elb")
    def test_get_stack_name(self, get_first_public_elb_function,
                            get_zone_id_function,
                            get_legacy_name_function,
                            get_zone_name_function,
                            get_connection_function):
        '''
        test if it returns correct stack name
        Args:
            get_first_public_elb_function: get_first_public_elb()
            get_zone_id_function: get_zone_id()
            get_legacy_name_function: get_legacy_name(): [application-environment]
            get_zone_name_function: get_zone_name()
            get_connection_function: get_connection(klass)
        '''
        get_connection_function.side_effect = self.connection_side_effect

        stack_name = fab_tasks.get_stack_name(False)
        self.assertTrue(stack_name)
        self.assertEqual(stack_name, "unittest-dev-12345678")

    @patch('bootstrap_cfn.fab_tasks.get_env_tag', return_value="newdev")
    @patch('bootstrap_cfn.fab_tasks.get_connection')
    @patch('bootstrap_cfn.fab_tasks.get_zone_name', return_value="dsd.io")
    @patch('bootstrap_cfn.fab_tasks.get_legacy_name', return_value="unittest-dev")
    @patch('bootstrap_cfn.fab_tasks.get_zone_id', return_value="ASDAKSLDK")
    @patch('bootstrap_cfn.fab_tasks.get_first_public_elb', return_value="unittest_elb")
    def test_set_stack_name(self, get_first_public_elb_function,
                            get_zone_id_function,
                            get_legacy_name_function,
                            get_zone_name_function,
                            get_connection_function,
                            get_env_tag_function):
        '''
        Test set_stack_name
        Args:
            get_first_public_elb_function: get_first_public_elb()
            get_zone_id_function: get_zone_id()
            get_legacy_name_function: get_legacy_name(): [application-environment]
            get_zone_name_function: get_zone_name()
            get_connection_function: get_connection(klass)
        Returns:

        '''
        get_connection_function.side_effect = self.connection_side_effect
        stack_name = fab_tasks.set_stack_name()
        self.assertTrue(stack_name)

    @patch('bootstrap_cfn.fab_tasks.get_basic_config')
    def test_get_zone_name(self, get_basic_config_function):
        '''
        Check if it returns the right zone name
        get_basic_config_function: get basic configuration yaml
        '''
        get_basic_config_function.return_value = yaml.load(set_up_basic_config())
        zone_name = fab_tasks.get_zone_name()
        self.assertEqual(zone_name, "dsd.io")

    @patch('bootstrap_cfn.fab_tasks.get_zone_name', return_value="dsd.io")
    def test_get_zone_id(self, get_zone_name_function):
        '''
        Check if it returns right zone id
        Args:
            get_zone_name_function: mock of get_zone_name
        '''
        # mock r53
        r53_mock = Mock()
        r53_connect_result = Mock(name='cf_connect')
        r53_mock.return_value = r53_connect_result
        response = {'GetHostedZoneResponse': {
            "HostedZone": {
                "Id": "/hostedzone/Z1GDM6HEODZI69"
            }
        }}
        # get_hosted_zone_by_name is within get_hosted_zone_id()
        mock_config = {'get_hosted_zone_by_name.return_value': response}
        r53_connect_result.configure_mock(**mock_config)
        boto.route53.connect_to_region = r53_mock
        r = r53.R53("profile_name")
        fab_tasks.get_connection = Mock(return_value=r)

        zone_id = fab_tasks.get_zone_id()
        self.assertEqual(zone_id, "Z1GDM6HEODZI69")

    @patch('bootstrap_cfn.fab_tasks.get_env_application', return_value="unittest-dev")
    @patch('bootstrap_cfn.fab_tasks.get_connection')
    @patch('bootstrap_cfn.fab_tasks.get_zone_name', return_value="dsd.io")
    @patch('bootstrap_cfn.fab_tasks.get_legacy_name', return_value="unittest-dev")
    @patch('bootstrap_cfn.fab_tasks.get_zone_id', return_value="ASDAKSLDK")
    def test_get_stack_list(self, get_zone_id_function,
                            get_legacy_name_function,
                            get_zone_name_function,
                            get_connection_function,
                            get_env_application_function):
        '''
        Test set_stack_name
        Args:
            get_zone_id_function: get_zone_id()
            get_legacy_name_function: get_legacy_name(): [application-environment]
            get_zone_name_function: get_zone_name()
            get_connection_function: get_connection(klass)
        Returns:

        '''
        get_connection_function.side_effect = self.connection_side_effect
        stack_count = fab_tasks.get_stack_list()
        self.assertEqual(stack_count, 2)
