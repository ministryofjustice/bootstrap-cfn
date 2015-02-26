#!/usr/bin/env python

import unittest
from helpers.config import ProjectConfig, AWSConfig, ConfigParser


class TestConfig(unittest.TestCase):

    def setUp(self):
        pass

    def test_project_config(self):
        '''
        Test the file is valid YAML and takes and environment
        '''
        config = ProjectConfig('sample-project.yaml', 'dev')
        self.assertEquals(
            sorted(
                config.config.keys()), [
                'ec2', 'elb', 'rds', 's3'])

    def test_project_config_merge_password(self):
        '''
        Test the two config files merge properly by ensuring elements from both files are present
        '''
        config = ProjectConfig(
            'sample-project.yaml',
            'dev',
            'sample-project-passwords.yaml')
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
            AWSConfig('dev', 'config_unknown.yaml')

    def test_aws_config_valid(self):
        '''
        Test the AWS config file is setup correctly
        '''
        config = AWSConfig('dev', 'config.yaml')
        self.assertEquals(config.aws_access, 'AKIAI***********')
        self.assertEquals(
            config.aws_secret,
            '*******************************************')

    def test_aws_config_invalid_env(self):
        '''
        Test the AWS config file errors on invalid environment
        '''
        with self.assertRaises(KeyError):
            AWSConfig('unknown', 'config.yaml')


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
        config = ConfigParser(None)
        self.assertEquals(known, config.iam())

    def test_s3(self):
        known = {
            'StaticBucketPolicy': {
                'Type': 'AWS::S3::BucketPolicy',
                'Properties': {
                    'PolicyDocument': {
                        'Statement': [
                            {
                                'Action': 's3:GetObject',
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
                'sample-project.yaml',
                'dev').config)
        config = ConfigParser(ProjectConfig('sample-project.yaml', 'dev').config)
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
                'sample-project.yaml',
                'dev',
                'sample-project-passwords.yaml').config)
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
                'sample-project.yaml',
                'dev').config)
        self.assertEquals(known, config.elb())

    def test_ec2(self):
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
                                                                                                   'wget https://raw.githubusercontent.com/ministryofjustice/bootstrap-cfn/master/bootstrap-salt.sh -O /tmp/moj-bootstrap.sh\n',
                                                                                                   'chmod 755 /tmp/moj-bootstrap.sh\n',
                                                                                                   '/tmp/moj-bootstrap.sh ']]}},
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
                'sample-project.yaml',
                'dev').config)
        self.assertEquals(known, config.ec2())


if __name__ == '__main__':
    unittest.main()
