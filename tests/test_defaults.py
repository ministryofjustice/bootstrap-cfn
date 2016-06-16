#!/usr/bin/env python
import unittest

from testfixtures import compare

import yaml

from bootstrap_cfn.config import ProjectConfig, utils


class TestDefaults(unittest.TestCase):
    """
    Test the use of default cloudformation values. Ensuring that they
    are applied where they should be, and user values are where they should be.
    """

    def setUp(self):
        pass

    def test_merge_config(self):
        environment = 'prod'
        config_data = ProjectConfig(config='tests/cloudformation/sample-project_minimal.yaml',
                                    passwords='tests/cloudformation/sample-project_minimal-secrets.yaml',
                                    environment=environment).config

        user_settings = yaml.load(open('tests/cloudformation/sample-project_minimal.yaml').read()).get(environment)
        passwords_settings = yaml.load(open('tests/cloudformation/sample-project_minimal-secrets.yaml').read()).get(environment)
        default_settings = yaml.load(open('bootstrap_cfn/config_defaults.yaml').read()).get(environment)
        merged_user_config = utils.dict_merge(user_settings, passwords_settings)

        for key, value in config_data.iteritems():
            print('TestDefaults::test_merge_config: Found %s=%s' % (key, value))
            if key == 'ec2':
                user_keys = ['tags', 'security_groups']
            elif key == 'selb':
                # Test values that should come from the user config
                user_keys = ['tags', 'security_groups']
            elif key == 'rds':
                # Test values that should come from the user config
                user_keys = ['db-name', 'db-master-username', 'db-master-password']
            elif key == 'elasticache':
                # Test values that should come from the user config
                user_keys = []
            else:
                # Skip keys we haven't specifically set up checks for
                print('TestDefaults::test_merge_config: Skipping checking the %s config section.' % (key))
                continue

            print('TestDefaults::test_merge_config: Checking the %s config section.' % (key))
            self.compare_settings(actual_settings=value,
                                  user_settings=merged_user_config.get(key, {}),
                                  default_settings=default_settings.get(key, {}),
                                  user_keys=user_keys)

    def compare_settings(self,
                         actual_settings,
                         user_settings,
                         default_settings,
                         user_keys):
        """
        Compare settings depending on whether they should be set by the user
        or as a default

        Args:
            actual_settings(dict): The settings in the actual config data
            user_settings(dict): The settings the user specified
            default_settings(dict): The settings the defaults specified
            user_keys(dict): The settings that should be set by the user config
        """
        for subkey, subvalue in actual_settings.iteritems():
            if subkey not in user_keys:
                defaults_subvalue = default_settings.get(subkey, {})
                print('TestDefaults::test_merge_config: Checking %s=%s is set to default settings'
                      % (subkey, defaults_subvalue))
                compare(subvalue, defaults_subvalue)
            else:
                user_subvalue = user_settings.get(subkey, {})
                print('TestDefaults::test_merge_config: Checking %s=%s is set to users setting'
                      % (subkey, user_subvalue))
                compare(subvalue, user_subvalue)
