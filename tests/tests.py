#!/usr/bin/env python

import unittest
from bootstrap_cfn.config import ProjectConfig, AWSConfig, ConfigParser
import bootstrap_cfn.errors as errors

class TestConfig(unittest.TestCase):

    def setUp(self):
        pass

    def test_project_config(self):
        '''
        Test the file is valid YAML and takes and environment
        '''
        config = ProjectConfig('tests/sample-project.yaml', 'dev')
        self.assertEquals(
            sorted(
                config.config.keys()), [
                'ec2', 'elb', 'rds', 's3','ssl'])

    def test_project_config_merge_password(self):
        '''
        Test the two config files merge properly by ensuring elements from both files are present
        '''
        config = ProjectConfig(
            'tests/sample-project.yaml',
            'dev',
            'tests/sample-project-passwords.yaml')
        self.assertEquals(
            config.config['rds']['instance-class'],
            'db.t2.micro')
        self.assertEquals(
            config.config['rds']['db-master-password'],
            'testpassword')

    def test_aws_config_invalid_file(self):
        '''
        Test the AWS config file errors on invalid file
        '''

        with self.assertRaises(IOError):
            AWSConfig('dev', 'tests/config_unknown.yaml')

    def test_aws_config_valid(self):
        '''
        Test the AWS config file is setup correctly
        '''
        config = AWSConfig('dev', 'tests/config.yaml')
        self.assertEquals(config.aws_access, 'AKIAI***********')
        self.assertEquals(
            config.aws_secret,
            '*******************************************')

    def test_aws_config_invalid_env(self):
        '''
        Test the AWS config file errors on invalid environment
        '''
        with self.assertRaises(KeyError):
            AWSConfig('unknown', 'tests/config.yaml')


class TestConfigParser(unittest.TestCase):

    def setUp(self):
        self.maxDiff = 3000

    def test_iam(self):
        known = {'RolePolicies': {'Type': 'AWS::IAM::Policy',
                                  'Properties': {'PolicyName': 'BaseHost',
                                                 'PolicyDocument': {'Statement': [{'Action': ['autoscaling:Describe*'],
                                                                                   'Resource': '*',
                                                                                   'Effect': 'Allow'},
                                                                                  {'Action': ['ec2:Describe*'],
                                                                                   'Resource': '*',
                                                                                   'Effect': 'Allow'},
                                                                                  {'Action': ['rds:Describe*'],
                                                                                   'Resource': '*',
                                                                                   'Effect': 'Allow'},
                                                                                  {'Action': ['elasticache:Describe*'],
                                                                                   'Resource': '*',
                                                                                   'Effect': 'Allow'},
                                                                                  {'Action': ['s3:List*'],
                                                                                   'Resource': '*',
                                                                                   'Effect': 'Allow'}]},
                                                 'Roles': [{'Ref': 'BaseHostRole'}]}},
                 'InstanceProfile': {'Type': 'AWS::IAM::InstanceProfile',
                                     'Properties': {'Path': '/',
                                                    'Roles': [{'Ref': 'BaseHostRole'}]}},
                 'BaseHostRole': {'Type': 'AWS::IAM::Role',
                                  'Properties': {'Path': '/',
                                                 'AssumeRolePolicyDocument': {'Statement': [{'Action': ['sts:AssumeRole'],
                                                                                             'Effect': 'Allow',
                                                                                             'Principal': {'Service': ['ec2.amazonaws.com']}}]}}}}
        config = ConfigParser(None, 'my-stack-name')
        self.assertEquals(known, config.iam())

    def test_s3(self):
        known = {
            'StaticBucketPolicy': {
                'Type': 'AWS::S3::BucketPolicy',
                'Properties': {
                    'PolicyDocument': {
                        'Statement': [
                            {
                                'Action': [
                                    's3:Get*',
                                    's3:Put*',
                                    's3:List*'],
                                'Resource': 'arn:aws:s3:::moj-test-dev-static/*',
                                'Effect': 'Allow',
                                'Principal': {
                                    'AWS': '*'}}]},
                    'Bucket': {
                        'Ref': 'StaticBucket'}}},
            'StaticBucket': {
                'Type': 'AWS::S3::Bucket',
                'Properties': {
                    'AccessControl': 'BucketOwnerFullControl',
                    'BucketName': 'moj-test-dev-static'}}}
        config = ConfigParser(
            ProjectConfig(
                'tests/sample-project.yaml',
                'dev').config, 'my-stack-name')
        config = ConfigParser(ProjectConfig('tests/sample-project.yaml', 'dev').config, 'my-stack-name')
        self.assertEquals(known, config.s3())

    def test_rds(self):
        known = {
            'RDSInstance': {
                'Type': 'AWS::RDS::DBInstance',
                'Properties': {
                    'AllocatedStorage': 5,
                    'AllowMajorVersionUpgrade': False,
                    'AutoMinorVersionUpgrade': False,
                    'BackupRetentionPeriod': 1,
                    'DBInstanceClass': 'db.t2.micro',
                    'DBInstanceIdentifier': 'test-dev',
                    'DBName': 'test',
                    'DBSecurityGroups': [{'Ref': 'StackDBSecurityGroup'}],
                    'Engine': 'postgres',
                    'EngineVersion': '9.3.5',
                    'MasterUserPassword': 'testpassword',
                    'MasterUsername': 'testuser',
                    'MultiAZ': False,
                    'PubliclyAccessible': False,
                    'StorageType': 'gp2', }},
            'StackDBSecurityGroup': {
                'Type': 'AWS::RDS::DBSecurityGroup',
                'Properties': {
                    'DBSecurityGroupIngress': {'CIDRIP': '172.31.0.0/16'},
                    'GroupDescription': 'Ingress for CIDRIP'}}
        }

        config = ConfigParser(
            ProjectConfig(
                'tests/sample-project.yaml',
                'dev',
                'tests/sample-project-passwords.yaml').config,'my-stack-name')
        self.assertEquals(known, config.rds())

    def test_elb(self):
        known = [{'ELBtestdevexternal': {'Type': 'AWS::ElasticLoadBalancing::LoadBalancer',
                                         'Properties': {'Listeners': [{'InstancePort': 80,
                                                                       'LoadBalancerPort': 80,
                                                                       'Protocol': 'TCP'},
                                                                      {'InstancePort': 443,
                                                                       'LoadBalancerPort': 443,
                                                                       'Protocol': 'TCP'}],
                                                        'AvailabilityZones': {'Fn::GetAZs': ''},
                                                        'Scheme': 'internet-facing',
                                                        'LoadBalancerName': 'ELB-test-dev-external'}}},
                 {'DNStestdevexternal': {'Type': 'AWS::Route53::RecordSetGroup',
                                         'Properties': {'HostedZoneName': 'kyrtest.pf.dsd.io.',
                                                        'Comment': 'Zone apex alias targeted to ElasticLoadBalancer.',
                                                        'RecordSets': [{'AliasTarget': {'HostedZoneId': {'Fn::GetAtt': ['ELBtestdevexternal',
                                                                                                                        'CanonicalHostedZoneNameID']},
                                                                                        'DNSName': {'Fn::GetAtt': ['ELBtestdevexternal',
                                                                                                                   'CanonicalHostedZoneName']}},
                                                                        'Type': 'A',
                                                                        'Name': 'test-dev-external.kyrtest.pf.dsd.io.'}]}}},
                 {'ELBtestdevinternal': {'Type': 'AWS::ElasticLoadBalancing::LoadBalancer',
                                         'Properties': {'Listeners': [{'InstancePort': 80,
                                                                       'LoadBalancerPort': 80,
                                                                       'Protocol': 'TCP'}],
                                                        'AvailabilityZones': {'Fn::GetAZs': ''},
                                                        'Scheme': 'internet-facing',
                                                        'LoadBalancerName': 'ELB-test-dev-internal'}}},
                 {'DNStestdevinternal': {'Type': 'AWS::Route53::RecordSetGroup',
                                         'Properties': {'HostedZoneName': 'kyrtest.pf.dsd.io.',
                                                        'Comment': 'Zone apex alias targeted to ElasticLoadBalancer.',
                                                        'RecordSets': [{'AliasTarget': {'HostedZoneId': {'Fn::GetAtt': ['ELBtestdevinternal',
                                                                                                                        'CanonicalHostedZoneNameID']},
                                                                                        'DNSName': {'Fn::GetAtt': ['ELBtestdevinternal',
                                                                                                                   'CanonicalHostedZoneName']}},
                                                                        'Type': 'A',
                                                                        'Name': 'test-dev-internal.kyrtest.pf.dsd.io.'}]}}}]
        config = ConfigParser(
            ProjectConfig(
                'tests/sample-project.yaml',
                'dev').config,'my-stack-name')
        self.assertEquals(known, config.elb())

    def test_elb_missing_cert(self):
        from testfixtures import compare

        self.maxDiff = None
        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        # Ugh. Fixtures please?
        project_config.config.pop('ssl')
        project_config.config['elb'] = [{
            'name': 'dev_docker-registry.service',
            'hosted_zone': 'kyrtest.foo.bar.',
            'certificate_name': 'my-cert',
            'scheme': 'internet-facing',
            'listeners': [
                { 'LoadBalancerPort': 80,
                  'InstancePort': 80,
                  'Protocol': 'TCP'
                },
                { 'LoadBalancerPort': 443,
                  'InstancePort': 443,
                  'Protocol': 'HTTPS'
                },
            ],
        }]
        config = ConfigParser(project_config.config,'my-stack-name')
        with self.assertRaises(errors.CfnConfigError):
            config.elb()

    def test_elb_missing_cert_name(self):
        from testfixtures import compare

        self.maxDiff = None
        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        # Ugh. Fixtures please?
        project_config.config['elb'] = [{
            'name': 'dev_docker-registry.service',
            'hosted_zone': 'kyrtest.foo.bar.',
            'scheme': 'internet-facing',
            'listeners': [
                { 'LoadBalancerPort': 80,
                  'InstancePort': 80,
                  'Protocol': 'TCP'
                },
                { 'LoadBalancerPort': 443,
                  'InstancePort': 443,
                  'Protocol': 'HTTPS'
                },
            ],
        }]
        config = ConfigParser(project_config.config,'my-stack-name')
        with self.assertRaises(errors.CfnConfigError):
            config.elb()

    def test_elb_with_ssl(self):
        from testfixtures import compare

        self.maxDiff = None
        known = [
            {
                'ELBdev_dockerregistryservice': {
                    'Type': 'AWS::ElasticLoadBalancing::LoadBalancer',
                    'Properties': {
                        'Listeners': [
                            {
                                'InstancePort': 80,
                                'LoadBalancerPort': 80,
                                'Protocol': 'TCP'
                            },
                            {
                                'InstancePort': 443,
                                'LoadBalancerPort': 443,
                                'Protocol': 'HTTPS',
                                'SSLCertificateId': {
                                    'Fn::Join': [
                                        '',
                                        [
                                            'arn:aws:iam::',
                                            {
                                                'Ref': 'AWS::AccountId'
                                            },
                                            ':server-certificate/',
                                            'my-cert-my-stack-name'
                                        ]
                                    ]
                                }
                            }
                        ],
                        'AvailabilityZones': {'Fn::GetAZs': ''},
                        'Scheme': 'internet-facing',
                        'LoadBalancerName': 'ELB-dev_docker-registryservice'}
                }
            },
            {
                'DNSdev_dockerregistryservice': {
                    'Type': 'AWS::Route53::RecordSetGroup',
                    'Properties': {
                        'HostedZoneName': 'kyrtest.foo.bar.',
                        'Comment': 'Zone apex alias targeted to ElasticLoadBalancer.',
                        'RecordSets': [
                            {'AliasTarget': {'HostedZoneId': {'Fn::GetAtt': ['ELBdev_dockerregistryservice', 'CanonicalHostedZoneNameID']},
                                             'DNSName': {'Fn::GetAtt': ['ELBdev_dockerregistryservice', 'CanonicalHostedZoneName']}},
                             'Type': 'A',
                             'Name': 'dev_docker-registry.service.kyrtest.foo.bar.'}
                        ]
                    }
                }
            }
        ]
        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        # Ugh. Fixtures please?
        project_config.config['elb'] = [{
            'name': 'dev_docker-registry.service',
            'hosted_zone': 'kyrtest.foo.bar.',
            'scheme': 'internet-facing',
            'certificate_name': 'my-cert',
            'listeners': [
                { 'LoadBalancerPort': 80,
                  'InstancePort': 80,
                  'Protocol': 'TCP'
                },
                { 'LoadBalancerPort': 443,
                  'InstancePort': 443,
                  'Protocol': 'HTTPS'
                },
            ],
        }]
        config = ConfigParser(project_config.config,'my-stack-name')
        self.assertEquals(known, config.elb())

    def test_elb_with_reserved_chars(self):
        from testfixtures import compare

        self.maxDiff = None
        known = [
            {
                'ELBdev_dockerregistryservice': {
                    'Type': 'AWS::ElasticLoadBalancing::LoadBalancer',
                    'Properties': {
                        'Listeners': [
                            {
                                'InstancePort': 80,
                                'LoadBalancerPort': 80,
                                'Protocol': 'TCP'
                            },
                            {
                                'InstancePort': 443,
                                'LoadBalancerPort': 443,
                                'Protocol': 'TCP'
                            }
                        ],
                        'AvailabilityZones': {'Fn::GetAZs': ''},
                        'Scheme': 'internet-facing',
                        'LoadBalancerName': 'ELB-dev_docker-registryservice'}
                }
            },
            {
                'DNSdev_dockerregistryservice': {
                    'Type': 'AWS::Route53::RecordSetGroup',
                    'Properties': {
                        'HostedZoneName': 'kyrtest.foo.bar.',
                        'Comment': 'Zone apex alias targeted to ElasticLoadBalancer.',
                        'RecordSets': [
                            {'AliasTarget': {'HostedZoneId': {'Fn::GetAtt': ['ELBdev_dockerregistryservice', 'CanonicalHostedZoneNameID']},
                                             'DNSName': {'Fn::GetAtt': ['ELBdev_dockerregistryservice', 'CanonicalHostedZoneName']}},
                             'Type': 'A',
                             'Name': 'dev_docker-registry.service.kyrtest.foo.bar.'}
                        ]
                    }
                }
            }
        ]
        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        # Ugh. Fixtures please?
        project_config.config['elb'] = [{
            'name': 'dev_docker-registry.service',
            'hosted_zone': 'kyrtest.foo.bar.',
            'scheme': 'internet-facing',
            'listeners': [
                { 'LoadBalancerPort': 80,
                  'InstancePort': 80,
                  'Protocol': 'TCP'
                },
                { 'LoadBalancerPort': 443,
                  'InstancePort': 443,
                  'Protocol': 'TCP'
                },
            ],
        }]
        config = ConfigParser(project_config.config,'my-stack-name')
        self.assertEquals(known, config.elb())

    def test_ec2(self):

        self.maxDiff = None

        known = {'ScalingGroup': {'Type': 'AWS::AutoScaling::AutoScalingGroup',
                                  'Properties': {'DesiredCapacity': 1,
                                                 'Tags': [{'PropagateAtLaunch': True,
                                                           'Value': 'docker',
                                                           'Key': 'Role'},
                                                          {'PropagateAtLaunch': True,
                                                           'Value': 'test',
                                                           'Key': 'Apps'},
                                                          {'PropagateAtLaunch': True,
                                                           'Value': 'dev',
                                                           'Key': 'Env'}],
                                                 'MinSize': 0,
                                                 'MaxSize': 3,
                                                 'LaunchConfigurationName': {'Ref': 'BaseHostLaunchConfig'},
                                                 'AvailabilityZones': {'Fn::GetAZs': ''}}},
                 'BaseHostSG': {'Type': 'AWS::EC2::SecurityGroup',
                                'Properties': {'SecurityGroupIngress': [{'ToPort': 22,
                                                                         'IpProtocol': 'tcp',
                                                                         'FromPort': 22,
                                                                         'CidrIp': '0.0.0.0/0'},
                                                                        {'ToPort': 80,
                                                                         'IpProtocol': 'tcp',
                                                                         'FromPort': 80,
                                                                         'CidrIp': '0.0.0.0/0'}],
                                               'GroupDescription': 'BaseHost Security Group'}},
                 'BaseHostLaunchConfig': {'Type': 'AWS::AutoScaling::LaunchConfiguration',
                                          'Properties': {'UserData': {'Fn::Base64': {'Fn::Join': ['',
                                                                                                  ['#!/bin/bash -xe\n',
                                                                                                   '#do nothing for now']]}},
                                                         'ImageId': {'Fn::FindInMap': ['AWSRegion2AMI',
                                                                                       {
                                                                                           'Ref': 'AWS::Region'},
                                                                                       'AMI']},
                                                         'KeyName': 'default',
                                                         'BlockDeviceMappings': [{'DeviceName': '/dev/sda1',
                                                                                  'Ebs': {'VolumeSize': 10}},
                                                                                 {'DeviceName': '/dev/sdf',
                                                                                  'Ebs': {'VolumeSize': 10}}],
                                                         'SecurityGroups': [{'Ref': 'BaseHostSG'}],
                                                         'IamInstanceProfile': {'Ref': 'InstanceProfile'},
                                                         'InstanceType': 't2.micro'}}}
        config = ConfigParser(
            ProjectConfig(
                'tests/sample-project.yaml',
                'dev').config, 'my-stack-name')
        self.assertEquals(known, config.ec2())


if __name__ == '__main__':
    unittest.main()
