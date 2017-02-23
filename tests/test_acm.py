#!/usr/bin/env python
import json
import unittest

from testfixtures import compare

from troposphere.certificatemanager import Certificate, DomainValidationOption

from bootstrap_cfn.config import ConfigParser, ProjectConfig


class TestConfig(unittest.TestCase):

    def setUp(self):
        pass


class TestConfigParser(unittest.TestCase):

    def _resources_to_dict(self, resources):
        resources_dict = {}
        for resource in resources:
            resources_dict[resource.title] = resource.to_dict()
        return json.loads(json.dumps(resources_dict))

    def test_acm(self):
        project_config = ProjectConfig('tests/cloudformation/sample-project_acm.yaml', 'dev')
        config_parser = ConfigParser(project_config.config, 'my-stack-name')
        certificate_name = 'mycert'
        domain_name = 'helloworld.test.dsd.io'
        validation_domain = 'dsd.io'
        tags = [{
            'Key': 'Name',
            'Value': {'Fn::Join': ['', [{'Ref': u'AWS::StackName'}, '-', u'acm']]}},
            {'Key': 'test_key1', 'Value': 'test_value_1'},
            {'Key': 'test_key2', 'Value': 'test_value_2'}
        ]
        subject_alternative_names = ['goodbye.test.dsd.io', 'hello_again.test.dsd.io']

        domain_validation_options = DomainValidationOption(
            DomainName=domain_name,
            ValidationDomain=validation_domain
        )
        ACMCertificate = Certificate(
                certificate_name,
                DomainName=domain_name,
                SubjectAlternativeNames=subject_alternative_names,
                DomainValidationOptions=[domain_validation_options],
                Tags=tags
            )
        certificate_cfg = [config_parser._get_acm_certificate(certificate_name)]
        expected = [ACMCertificate]
        compare(self._resources_to_dict(expected),
                self._resources_to_dict(certificate_cfg))

    def test_acm_non_alphanumeric(self):
        project_config = ProjectConfig('tests/cloudformation/sample-project_acm.yaml', 'dev')
        config_parser = ConfigParser(project_config.config, 'my-stack-name')
        certificate_name = 'mycert-dev.something.io'
        parsed_certificate_name = 'mycertdevsomethingio'
        domain_name = 'helloworld.test.dsd.io'
        tags = [{
            'Key': 'Name',
            'Value': {'Fn::Join': ['', [{'Ref': u'AWS::StackName'}, '-', u'acm']]}}
        ]
        subject_alternative_names = []

        domain_validation_options = DomainValidationOption(
            DomainName=domain_name,
            ValidationDomain=domain_name
        )
        ACMCertificate = Certificate(
                parsed_certificate_name,
                DomainName=domain_name,
                SubjectAlternativeNames=subject_alternative_names,
                DomainValidationOptions=[domain_validation_options],
                Tags=tags
            )
        certificate_cfg = [config_parser._get_acm_certificate(certificate_name)]
        expected = [ACMCertificate]
        compare(self._resources_to_dict(expected),
                self._resources_to_dict(certificate_cfg))


if __name__ == '__main__':
    unittest.main()
