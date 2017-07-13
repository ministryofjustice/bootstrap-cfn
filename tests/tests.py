#!/usr/bin/env python
import json
import unittest
from StringIO import StringIO

from mock import patch

from testfixtures import compare

from troposphere import Base64, FindInMap, GetAZs, GetAtt, Join, Ref, Template, ec2, iam, rds, s3
from troposphere.autoscaling import AutoScalingGroup, LaunchConfiguration, Tag
from troposphere.ec2 import SecurityGroup, SecurityGroupIngress
from troposphere.elasticache import ReplicationGroup, SubnetGroup
from troposphere.elasticloadbalancing import ConnectionDrainingPolicy, HealthCheck, LoadBalancer, Policy
from troposphere.iam import PolicyType
from troposphere.route53 import RecordSetGroup

import yaml

from bootstrap_cfn import errors
from bootstrap_cfn import mime_packer
from bootstrap_cfn.config import ConfigParser, ProjectConfig


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
                'ec2', 'elasticache', 'elb', 'rds', 's3', 'ssl', 'vpc'])

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


class TestConfigParser(unittest.TestCase):

    def setUp(self):
        self.maxDiff = 9000

    def _resources_to_dict(self, resources):
        resources_dict = {}
        for resource in resources:
            resources_dict[resource.title] = resource.to_dict()
        return json.loads(json.dumps(resources_dict))

    def test_iam_default(self):
        basehost_role = iam.Role('BaseHostRole')
        basehost_role.Path = '/'
        basehost_role.AssumeRolePolicyDocument = {
            'Statement': [{'Action': ['sts:AssumeRole'],
                           'Effect': 'Allow',
                           'Principal': {'Service': ['ec2.amazonaws.com']}}
                          ]
        }
        basehost_role_ref = Ref(basehost_role)

        role_policy = iam.PolicyType('RolePolicies')
        role_policy.PolicyName = 'BaseHost'
        role_policy.PolicyDocument = {
            'Statement': [
                {'Action': ['autoscaling:Describe*'],
                 'Resource': '*',
                 'Effect': 'Allow'},
                {'Action': ['cloudformation:Describe*'],
                 'Resource': '*',
                 'Effect': 'Allow'},
                {'Action': ['elasticloadbalancing:Describe*'],
                 'Effect': 'Allow',
                 'Resource': '*'}
                ]
        }
        role_policy.Roles = [basehost_role_ref]

        instance_profile = iam.InstanceProfile('InstanceProfile')
        instance_profile.Path = '/'
        instance_profile.Roles = [basehost_role_ref]

        config = ConfigParser({}, 'my-stack-name')
        known = [role_policy, instance_profile, basehost_role]
        known = self._resources_to_dict(known)
        iam_dict = self._resources_to_dict(config.iam())
        compare(known, iam_dict)

    def test_iam(self):
        """
        Test the case when all the components that can have IAM actions are enabled
        """
        basehost_role = iam.Role('BaseHostRole')
        basehost_role.Path = '/'
        basehost_role.AssumeRolePolicyDocument = {
            'Statement': [{'Action': ['sts:AssumeRole'],
                           'Effect': 'Allow',
                           'Principal': {'Service': ['ec2.amazonaws.com']}}
                          ]
        }
        basehost_role_ref = Ref(basehost_role)

        role_policy = iam.PolicyType('RolePolicies')
        role_policy.PolicyName = 'BaseHost'
        role_policy.PolicyDocument = {
            'Statement': [
                {'Action': ['autoscaling:Describe*'],
                 'Resource': '*',
                 'Effect': 'Allow'},
                {'Action': ['cloudformation:Describe*'],
                 'Resource': '*',
                 'Effect': 'Allow'},
                {'Action': ['elasticloadbalancing:Describe*'],
                 'Resource': '*',
                 'Effect': 'Allow'},
                {'Action': ['ec2:Describe*'],
                 'Resource': '*',
                 'Effect': 'Allow'},
                {'Action': ['ec2:CreateTags'],
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
                 'Effect': 'Allow'}]
        }
        role_policy.Roles = [basehost_role_ref]

        instance_profile = iam.InstanceProfile('InstanceProfile')
        instance_profile.Path = '/'
        instance_profile.Roles = [basehost_role_ref]
        # Setup config with dummy config sections so that policies are generated for those components
        config = ConfigParser({'ec2': {}, 'rds': {}, 's3': {}, 'elasticache': {}}, 'my-stack-name')
        known = [role_policy, instance_profile, basehost_role]
        known = self._resources_to_dict(known)
        iam_dict = self._resources_to_dict(config.iam())
        compare(known, iam_dict)

    def test_s3(self):
        bucket = s3.Bucket('StaticBucket')
        bucket.AccessControl = 'BucketOwnerFullControl'
        bucket.BucketName = 'moj-test-dev-static'
        bucket_ref = Ref(bucket)

        static_bp = s3.BucketPolicy('StaticBucketPolicy')
        resource_value = Join("", ["arn:aws:s3:::", {"Ref": "StaticBucket"}, "/*"])

        static_bp.PolicyDocument = {
            'Statement': [
                {
                    'Action': [
                        's3:GetObject'],
                    'Resource': resource_value,
                    'Effect': 'Allow',
                    'Principal': '*'
                }
            ]
        }
        static_bp.Bucket = bucket_ref

        config = ConfigParser(
            ProjectConfig(
                'tests/sample-project.yaml',
                'dev').config,
            'my-stack-name')

        # Create S3 resources in template
        template = Template()
        config.s3(template)
        resources = template.resources.values()

        compare(self._resources_to_dict([static_bp, bucket]),
                self._resources_to_dict(resources))

        # Test for outputs
        expected_outputs = {
            "StaticBucketName": {
                "Description": "S3 bucket name",
                "Value": {"Ref": "StaticBucket"}
            }
        }
        actual_outputs = self._resources_to_dict(template.outputs.values())
        compare(expected_outputs, actual_outputs)

    def test_s3_no_subkeys(self):
        """
        Test that a config with the s3: key alone will load
        """
        bucket = s3.Bucket('StaticBucket')
        bucket.AccessControl = 'BucketOwnerFullControl'
        bucket_ref = Ref(bucket)

        static_bp = s3.BucketPolicy('StaticBucketPolicy')
        resource_value = Join("", ["arn:aws:s3:::", {"Ref": "StaticBucket"}, "/*"])

        static_bp.PolicyDocument = {
            'Statement': [
                {
                    'Action': [
                        's3:GetObject'],
                    'Resource': resource_value,
                    'Effect': 'Allow',
                    'Principal': '*'
                }
            ]
        }
        static_bp.Bucket = bucket_ref

        # Load project config and wipe out all s3 subkeys
        base_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        base_config.config["s3"] = None
        config = ConfigParser(base_config.config,
                              'my-stack-name')
        # Create S3 resources in template
        template = Template()
        config.s3(template)
        resources = template.resources.values()

        compare(self._resources_to_dict([static_bp, bucket]),
                self._resources_to_dict(resources))
        # Test for outputs
        expected_outputs = {
            "StaticBucketName": {
                "Description": "S3 bucket name",
                "Value": {"Ref": "StaticBucket"}
            }
        }
        actual_outputs = self._resources_to_dict(template.outputs.values())
        compare(expected_outputs, actual_outputs)

    def test_s3_custom_policy(self):
        resource_value = 'arn:aws:s3:::moj-test-dev-static/*'
        expected_s3 = [
            {
                'Action': [
                    's3:Get*',
                    's3:Put*',
                    's3:List*',
                    's3:Delete*'],
                'Resource': resource_value,
                'Effect': 'Allow',
                'Principal': {'AWS': '*'}
            }
        ]

        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')

        project_config.config['s3'] = {
            'static-bucket-name': 'moj-test-dev-static',
            'policy': 'tests/sample-custom-s3-policy.json'}

        config = ConfigParser(project_config.config, 'my-stack-name')

        # Create S3 resources in template
        template = Template()
        config.s3(template)
        resources = template.resources.values()

        s3_cfg = self._resources_to_dict(resources)
        s3_custom_cfg = s3_cfg['StaticBucketPolicy'][
            'Properties']['PolicyDocument']['Statement']

        compare(expected_s3, s3_custom_cfg)

        # Test for outputs
        expected_outputs = {
            "StaticBucketName": {
                "Description": "S3 bucket name",
                "Value": {"Ref": "StaticBucket"}
            }
        }
        actual_outputs = self._resources_to_dict(template.outputs.values())
        compare(expected_outputs, actual_outputs)

    def test_s3_wrong_lifecycles(self):
        '''
        Tests an s3 scenario where the lifecycles is not a dict
        '''
        conf_under_test = {
            'buckets': [
                {
                    'name': 'testbucket1',
                    'lifecycles': {
                        '/directory2': [],
                    }
                }
            ]
        }

        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        project_config.config['s3'] = conf_under_test
        config = ConfigParser(project_config.config, 'my-stack-name')

        with self.assertRaises(errors.CfnConfigError):
            template = Template()
            config.s3(template)

    def test_s3_noexpirationdays(self):
        '''
        Tests an s3 scenario where the lifecycles is not a dict
        '''
        conf_under_test = {
            'buckets': [
                {
                    'name': 'testbucket1',
                    'lifecycles': {
                        '/directory1': {'noexpirationdays': 154},
                    }
                }
            ]
        }

        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        project_config.config['s3'] = conf_under_test
        config = ConfigParser(project_config.config, 'my-stack-name')

        with self.assertRaises(errors.CfnConfigError):
            template = Template()
            config.s3(template)

    def test_s3_total(self):
        '''
        Tests an s3 scenario with a static-bucket-name, and three buckets:
        - testbucket1 with a multiple overlapping lifecycle entries
        - testbucket2 with a single bucket lifecycle entry on a directory prefix
        - testbucket3 with an entire bucket lifecycle entry
        '''
        conf_under_test = {
            'static-bucket-name': 'moj-test-dev-static',
            'buckets': [
                {
                    'name': 'testbucket1',
                    'lifecycles': {
                        '/directory1': {'expirationdays': 60},
                        '/directory2': {'expirationdays': 80},
                        '/directory3': {'expirationdays': 90},
                        '/': {'expirationdays': 1}
                    }
                },
                {
                    'name': 'testbucket2',
                    'lifecycles': {
                        '/directory1': {'expirationdays': 5}
                    }
                },
                {
                    'name': 'testbucket3',
                    'lifecycles': {
                        '/': {'expirationdays': 2}
                    }
                }
            ]
        }

        # Resources to compare
        bucket = s3.Bucket('StaticBucket')
        bucket.AccessControl = 'BucketOwnerFullControl'
        bucket.BucketName = 'moj-test-dev-static'
        bucket_ref = Ref(bucket)

        static_bp = s3.BucketPolicy('StaticBucketPolicy')
        resource_value = Join("", ["arn:aws:s3:::", {"Ref": "StaticBucket"}, "/*"])

        static_bp.PolicyDocument = {
            'Statement': [
                {
                    'Action': [
                        's3:GetObject'],
                    'Resource': resource_value,
                    'Effect': 'Allow',
                    'Principal': '*'
                }
            ]
        }
        static_bp.Bucket = bucket_ref

        def _policy(x):
            return {
                'Action': ['s3:DeleteObject', 's3:GetObject', 's3:PutObject'],
                "Resource": Join("", ["arn:aws:s3:::", Ref(x), "/*"]),
                'Effect': 'Allow',
                'Principal': '*',
                "Condition": {
                    "StringEquals": {
                        "aws:sourceVpc": {"Ref": "VPC"}
                    }
                }
            }

        bucket1 = s3.Bucket("testbucket1",
                            AccessControl='BucketOwnerFullControl',
                            LifecycleConfiguration=s3.LifecycleConfiguration(
                                Rules=[s3.LifecycleRule(Id="lifecyclerule_root",
                                                        Status="Enabled",
                                                        ExpirationInDays=1)]))
        bucket_policy1 = s3.BucketPolicy(
            "{}Policy".format("testbucket1"),
            Bucket=Ref(bucket1),
            PolicyDocument={"Statement": [_policy(bucket1)]}
        )

        bucket2 = s3.Bucket("testbucket2",
                            AccessControl='BucketOwnerFullControl',
                            LifecycleConfiguration=s3.LifecycleConfiguration(
                                Rules=[s3.LifecycleRule(Id="lifecyclerule_directory1",
                                                        Prefix="/directory1",
                                                        Status="Enabled",
                                                        ExpirationInDays=5)]))
        bucket_policy2 = s3.BucketPolicy(
            "{}Policy".format("testbucket2"),
            Bucket=Ref(bucket2),
            PolicyDocument={"Statement": [_policy(bucket2)]}
        )

        bucket3 = s3.Bucket("testbucket3",
                            AccessControl='BucketOwnerFullControl',
                            LifecycleConfiguration=s3.LifecycleConfiguration(
                                Rules=[s3.LifecycleRule(Id="lifecyclerule_root",
                                                        Status="Enabled",
                                                        ExpirationInDays=2)]))
        bucket_policy3 = s3.BucketPolicy(
            "{}Policy".format("testbucket3"),
            Bucket=Ref(bucket3),
            PolicyDocument={"Statement": [_policy(bucket3)]}
        )

        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        project_config.config['s3'] = conf_under_test
        config = ConfigParser(project_config.config, 'my-stack-name')

        # Create S3 resources in template
        template = Template()
        config.s3(template)
        resources = template.resources.values()

        compare(self._resources_to_dict(resources),
                self._resources_to_dict([static_bp, bucket, bucket1, bucket_policy1,
                                         bucket2, bucket_policy2, bucket3, bucket_policy3]))

    def test_s3_additional_bucket_with_custom_policy(self):
        conf_under_test = {
            'buckets': [
                {
                    'name': 'testbucket',
                    'policy': 'tests/sample-s3-additional-bucket-custom-policy.json'
                }
            ]
        }

        # Resources to compare
        expected_bucket_policy = [
            {
                'Action': ['s3:Get*', 's3:Put*', 's3:List*', 's3:Delete*'],
                'Resource': 'arn:aws:s3:::testbucket/*',
                'Effect': 'Allow',
                'Principal': {'AWS': '*'}
            }
        ]

        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        project_config.config['s3'] = conf_under_test
        config = ConfigParser(project_config.config, 'my-stack-name')

        template = Template()
        config.s3(template)
        resources = template.resources.values()

        s3_cfg = self._resources_to_dict(resources)
        s3_bucket_policy = s3_cfg['testbucketPolicy']['Properties']['PolicyDocument']['Statement']

        compare(expected_bucket_policy, s3_bucket_policy)

    def test_s3_additional_bucket_with_multi_part_custom_policy(self):
        conf_under_test = {
            'buckets': [
                {
                    'name': 'testbucket',
                    'policy': 'tests/sample-s3-additional-bucket-multi-part-custom-policy.json'
                }
            ]
        }

        # Resources to compare
        expected_bucket_policy = [
            {
                'Action': ['s3:Get*', 's3:Put*', 's3:List*', 's3:Delete*'],
                'Resource': 'arn:aws:s3:::testbucket/*',
                'Effect': 'Allow',
                'Condition': {
                    'StringEquals': {
                        'aws:sourceVpc': {'Ref': 'VPC'}
                    }
                }
            },
            {
                'Action': ['s3:Put*'],
                'Resource': 'arn:aws:s3:::testbucket/*',
                'Effect': 'Deny',
                'Condition': {
                    'StringNotEquals': {
                        's3:x-amz-server-side-encryption': 'AES256'
                    }
                }
            }
        ]

        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        project_config.config['s3'] = conf_under_test
        config = ConfigParser(project_config.config, 'my-stack-name')

        template = Template()
        config.s3(template)
        resources = template.resources.values()

        s3_cfg = self._resources_to_dict(resources)
        s3_bucket_policy = s3_cfg['testbucketPolicy']['Properties']['PolicyDocument']['Statement']

        compare(expected_bucket_policy, s3_bucket_policy)

    def test_rds(self):

        template = Template()
        config = ConfigParser(
            ProjectConfig(
                'tests/sample-project.yaml',
                'dev',
                'tests/sample-project-passwords.yaml').config, 'my-stack-name-12345678')

        db_sg = ec2.SecurityGroup('DatabaseSG')
        db_sg.VpcId = Ref('VPC')
        db_sg.GroupDescription = 'SG for EC2 Access to RDS'
        db_sg.SecurityGroupIngress = [
            {"ToPort": 5432,
             "FromPort": 5432,
             "IpProtocol": "tcp",
             "CidrIp": FindInMap("SubnetConfig", "VPC", "CIDR")},
            {"ToPort": 1433,
             "FromPort": 1433,
             "IpProtocol": "tcp",
             "CidrIp": FindInMap("SubnetConfig", "VPC", "CIDR")},
            {"ToPort": 3306,
             "FromPort": 3306,
             "IpProtocol": "tcp",
             "CidrIp": FindInMap("SubnetConfig", "VPC", "CIDR")}
        ]
        db_sg.DependsOn = []

        db_subnet = rds.DBSubnetGroup('RDSSubnetGroup')
        db_subnet.SubnetIds = [Ref('SubnetA'), Ref('SubnetB'), Ref('SubnetC')]
        db_subnet.DBSubnetGroupDescription = 'VPC Subnets'

        db_instance = rds.DBInstance('RDSInstance', DependsOn=db_sg.title)
        db_instance.MultiAZ = False
        db_instance.MasterUsername = 'testuser'
        db_instance.MasterUserPassword = 'testpassword'
        db_instance.DBName = 'test'
        db_instance.PubliclyAccessible = False
        db_instance.StorageEncrypted = False
        db_instance.StorageType = 'gp2'
        db_instance.AllocatedStorage = 5
        db_instance.AllowMajorVersionUpgrade = False
        db_instance.AutoMinorVersionUpgrade = False
        db_instance.BackupRetentionPeriod = 1
        db_instance.DBInstanceClass = 'db.t2.micro'
        db_instance.Engine = 'postgres'
        db_instance.EngineVersion = '9.5.4'
        db_instance.VPCSecurityGroups = [GetAtt(db_sg, 'GroupId')]
        db_instance.DBSubnetGroupName = Ref(db_subnet)

        known = [db_instance, db_subnet, db_sg]

        config.rds(template)
        resources = template.resources.values()
        rds_dict = self._resources_to_dict(resources)
        # RDS dict will contain DBIdentifier, which is random.
        # So we check it seperately here then remove it
        self.assertTrue("DBInstanceIdentifier" in rds_dict["RDSInstance"]["Properties"],
                        "test_rds: template does not contain DBInstanceIdentifier")
        identifier = rds_dict["RDSInstance"]["Properties"]["DBInstanceIdentifier"]
        # Identifier can be optionally be defined in the yaml template for compatibility.
        # We're only testing the case where it's defined. If left undefined AWS will
        # generate a random one.
        self.assertEquals(identifier, 'test-dev-12345678')
        rds_dict["RDSInstance"]["Properties"].pop("DBInstanceIdentifier")
        known = self._resources_to_dict(known)
        compare(known, rds_dict)

        # Test for outputs
        expected_outputs = {
            "dbhost": {
                "Description": "RDS Hostname",
                "Value": {"Fn::GetAtt": ["RDSInstance", "Endpoint.Address"]}
            },
            "dbport": {
                "Description": "RDS Port",
                "Value": {
                    "Fn::GetAtt": ["RDSInstance", "Endpoint.Port"]
                }
            }
        }
        actual_outputs = self._resources_to_dict(template.outputs.values())
        compare(expected_outputs, actual_outputs)

    def test_rds_with_vpc_dependencies(self):
        template = Template()

        config = ConfigParser(
            ProjectConfig(
                'tests/sample-project.yaml',
                'dev',
                'tests/sample-project-passwords.yaml').config, 'my-stack-name-12345678')
        # generate and add the VPCGatewayAttachment resource to the template
        # to ensure it is passed as an attachment (DependsOn) later
        vpc_resources_needed_for_rds = [
            res for res in config.vpc()
            if res.resource_type == 'AWS::EC2::VPCGatewayAttachment']
        map(template.add_resource, vpc_resources_needed_for_rds)

        db_sg = ec2.SecurityGroup('DatabaseSG')
        db_sg.VpcId = Ref('VPC')
        db_sg.GroupDescription = 'SG for EC2 Access to RDS'
        db_sg.SecurityGroupIngress = [
            {"ToPort": 5432,
             "FromPort": 5432,
             "IpProtocol": "tcp",
             "CidrIp": FindInMap("SubnetConfig", "VPC", "CIDR")},
            {"ToPort": 1433,
             "FromPort": 1433,
             "IpProtocol": "tcp",
             "CidrIp": FindInMap("SubnetConfig", "VPC", "CIDR")},
            {"ToPort": 3306,
             "FromPort": 3306,
             "IpProtocol": "tcp",
             "CidrIp": FindInMap("SubnetConfig", "VPC", "CIDR")}
        ]
        db_sg.DependsOn = ["AttachGateway"]

        db_subnet = rds.DBSubnetGroup('RDSSubnetGroup')
        db_subnet.SubnetIds = [Ref('SubnetA'), Ref('SubnetB'), Ref('SubnetC')]
        db_subnet.DBSubnetGroupDescription = 'VPC Subnets'

        db_instance = rds.DBInstance('RDSInstance', DependsOn=db_sg.title)
        db_instance.MultiAZ = False
        db_instance.MasterUsername = 'testuser'
        db_instance.MasterUserPassword = 'testpassword'
        db_instance.DBName = 'test'
        db_instance.PubliclyAccessible = False
        db_instance.StorageEncrypted = False
        db_instance.StorageType = 'gp2'
        db_instance.AllocatedStorage = 5
        db_instance.AllowMajorVersionUpgrade = False
        db_instance.AutoMinorVersionUpgrade = False
        db_instance.BackupRetentionPeriod = 1
        db_instance.DBInstanceClass = 'db.t2.micro'
        db_instance.Engine = 'postgres'
        db_instance.EngineVersion = '9.5.4'
        db_instance.VPCSecurityGroups = [GetAtt(db_sg, 'GroupId')]
        db_instance.DBSubnetGroupName = Ref(db_subnet)

        known = [db_instance, db_subnet, db_sg]

        config.rds(template)
        resources = template.resources.values()
        rds_dict = self._resources_to_dict(resources)
        # RDS dict will contain DBIdentifier, which is random.
        # So we check it seperately here then remove it
        self.assertTrue("DBInstanceIdentifier" in rds_dict["RDSInstance"]["Properties"],
                        "test_rds_with_vpc_dependencies: "
                        "template does not contain DBInstanceIdentifier")
        identifier = rds_dict["RDSInstance"]["Properties"]["DBInstanceIdentifier"]
        # Identifier can be optionally be defined in the yaml template for compatibility.
        # We're only testing the case where it's defined. If left undefined AWS will
        # generate a random one.
        self.assertEquals(identifier, 'test-dev-12345678')
        rds_dict["RDSInstance"]["Properties"].pop("DBInstanceIdentifier")
        # keep just the keys (rds) we want to compare,
        # we are done with the vpc so pop the vpc gw attachment
        [rds_dict.pop(res.title) for res in vpc_resources_needed_for_rds]
        known = self._resources_to_dict(known)
        compare(known, rds_dict)

        # Test for outputs
        expected_outputs = {
            "dbhost": {
                "Description": "RDS Hostname",
                "Value": {"Fn::GetAtt": ["RDSInstance", "Endpoint.Address"]}
            },
            "dbport": {
                "Description": "RDS Port",
                "Value": {
                    "Fn::GetAtt": ["RDSInstance", "Endpoint.Port"]
                }
            }
        }
        actual_outputs = self._resources_to_dict(template.outputs.values())
        compare(expected_outputs, actual_outputs)

    def test_elasticache(self):
        es_sg = SecurityGroup(
            "ElasticacheSG",
            SecurityGroupIngress=[
                {"ToPort": 10024,
                 "FromPort": 10024,
                 "IpProtocol": "tcp",
                 "CidrIp": FindInMap("SubnetConfig", "VPC", "CIDR")}
            ],
            VpcId=Ref("VPC"),
            GroupDescription="SG for EC2 Access to Elasticache",
        )

        es_subnet_group = SubnetGroup(
            'ElasticacheSubnetGroup',
            Description="Elasticache Subnet Group",
            SubnetIds=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")]
            )

        elasticache_replication_group = ReplicationGroup(
            "ElasticacheReplicationGroup",
            ReplicationGroupDescription='Elasticache Replication Group',
            Engine='redis',
            NumCacheClusters=3,
            CacheNodeType='cache.m1.medium',
            SecurityGroupIds=[GetAtt(es_sg, "GroupId")],
            CacheSubnetGroupName=Ref(es_subnet_group),
            SnapshotArns=["arn:aws:s3:::somebucket/redis.rdb"],
            Port=10024
        )

        known = [elasticache_replication_group,
                 es_subnet_group,
                 es_sg]

        config = ConfigParser(
            ProjectConfig(
                'tests/sample-project.yaml',
                'dev',
                'tests/sample-project-passwords.yaml').config, 'my-stack-name')

        template = Template()
        config.elasticache(template)
        resources = template.resources.values()
        es_dict = self._resources_to_dict(resources)

        known = self._resources_to_dict(known)
        compare(known, es_dict)

        # Test for outputs
        expected_outputs = {
            "ElasticacheReplicationGroupName": {
                "Description": "Elasticache Replication Group Name",
                "Value": {"Ref": "ElasticacheReplicationGroup"}
            },
            "ElasticacheEngine": {
                "Description": "Elasticache Engine",
                "Value": "redis"
            }
        }
        actual_outputs = self._resources_to_dict(template.outputs.values())
        compare(expected_outputs, actual_outputs)

    def test_elb(self):
        lb = LoadBalancer(
            "ELBtestdevinternal",
            ConnectionDrainingPolicy=ConnectionDrainingPolicy(
                Enabled=True,
                Timeout=120,
            ),
            Subnets=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")],
            Listeners=[
                {
                    "InstancePort": 80,
                    "LoadBalancerPort": 80,
                    "Protocol": "TCP"
                }
            ],
            SecurityGroups=[Ref("DefaultSGtestdevinternal")],
            Scheme="internal",
            Policies=[
                Policy(
                    Attributes=[{'Name': "Reference-Security-Policy", 'Value': "ELBSecurityPolicy-2015-05"}],
                    PolicyType='SSLNegotiationPolicyType',
                    PolicyName='PinDownSSLNegotiationPolicy201505'
                )
            ]
        )

        pt1 = PolicyType(
            "Policytestdevexternal",
            PolicyName="testdevexternalBaseHost",
            PolicyDocument={
                "Statement": [
                    {
                        "Action":
                            ["elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                             "elasticloadbalancing:RegisterInstancesWithLoadBalancer"],
                        "Resource": [
                            Join(
                                "", ["arn:aws:elasticloadbalancing:",
                                     Ref("AWS::Region"), ":",
                                     Ref("AWS::AccountId"),
                                     ":loadbalancer/",
                                     {"Ref": "ELBtestdevexternal"}]
                            )],
                        "Effect": "Allow"}
                ]
            },
            Roles=[Ref("BaseHostRole")],
        )

        pt2 = PolicyType(
            "Policytestdevinternal",
            PolicyName="testdevinternalBaseHost",
            PolicyDocument={
                "Statement": [
                    {
                        "Action":
                            ["elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                             "elasticloadbalancing:RegisterInstancesWithLoadBalancer"],
                        "Resource":
                            [
                                Join("", ["arn:aws:elasticloadbalancing:",
                                          Ref("AWS::Region"), ":",
                                          Ref("AWS::AccountId"),
                                          ":loadbalancer/",
                                          {"Ref": "ELBtestdevinternal"}]
                                     )
                            ],
                        "Effect": "Allow"
                    }
                ]
            },
            Roles=[Ref("BaseHostRole")],
        )

        rs = RecordSetGroup(
            "DNStestdevexternal",
            Comment="Zone apex alias targeted to ElasticLoadBalancer.",
            HostedZoneName="kyrtest.pf.dsd.io.",
            RecordSets=[
                {
                    "Type": "A",
                    "AliasTarget": {
                        "HostedZoneId": GetAtt("ELBtestdevexternal",
                                               "CanonicalHostedZoneNameID"),
                        "DNSName": GetAtt("ELBtestdevexternal", "DNSName")
                    },
                    "Name": "test-dev-external-name.kyrtest.pf.dsd.io."
                }
            ],
        )

        rsg = RecordSetGroup(
            "DNStestdevinternal",
            Comment="Zone apex alias targeted to ElasticLoadBalancer.",
            HostedZoneName="kyrtest.pf.dsd.io.",
            RecordSets=[
                {
                    "Type": "A",
                    "AliasTarget": {
                        "HostedZoneId":
                            GetAtt(lb, "CanonicalHostedZoneNameID"),
                        "DNSName": GetAtt(lb, "DNSName")
                    },
                    "Name": "test-dev-internal-name.kyrtest.pf.dsd.io."
                }
            ],
        )

        lb2 = LoadBalancer(
            "ELBtestdevexternal",
            ConnectionDrainingPolicy=ConnectionDrainingPolicy(
                Enabled=True,
                Timeout=120,
            ),
            Subnets=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")],
            Listeners=[
                {"InstancePort": 80,
                 "LoadBalancerPort": 80,
                 "Protocol": "TCP"},
                {"InstancePort": 443,
                 "LoadBalancerPort": 443,
                 "Protocol": "TCP"}
            ],
            SecurityGroups=[Ref("DefaultSGtestdevexternal")],
            Scheme="internet-facing",
            Policies=[
                Policy(
                    Attributes=[{'Name': "Reference-Security-Policy", 'Value': "ELBSecurityPolicy-2015-05"}],
                    PolicyType='SSLNegotiationPolicyType',
                    PolicyName='PinDownSSLNegotiationPolicy201505'
                )
            ],
        )
        known_load_balancer_resources = [lb, lb2]
        known_policy_type_resources = [pt1, pt2]
        known_record_set_resources = [rs, rsg]

        expected_sgs = [
            SecurityGroup(
                "DefaultSGtestdevexternal",
                SecurityGroupIngress=[
                    {
                        "ToPort": 443,
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "CidrIp": "0.0.0.0/0"
                    },
                    {"ToPort": 80,
                     "IpProtocol": "tcp",
                     "FromPort": 80,
                     "CidrIp": "0.0.0.0/0"
                     }
                ],
                VpcId=Ref("VPC"),
                GroupDescription="DefaultELBSecurityGroup"),
            SecurityGroup(
                "DefaultSGtestdevinternal",
                SecurityGroupIngress=[
                    {"ToPort": 443,
                     "IpProtocol": "tcp",
                     "FromPort": 443,
                     "CidrIp": "0.0.0.0/0"
                     },
                    {
                        "ToPort": 80,
                        "IpProtocol": "tcp",
                        "FromPort": 80,
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                VpcId=Ref("VPC"),
                GroupDescription="DefaultELBSecurityGroup",
            )]

        config = ConfigParser(
            ProjectConfig(
                'tests/sample-project.yaml',
                'dev').config, 'my-stack-name')

        # Create elb resources with template
        template = Template()
        config.elb(template)
        elb_cfg = config._find_resources(template, "AWS::ElasticLoadBalancing::LoadBalancer")
        elb_pt = config._find_resources(template, "AWS::IAM::Policy")
        elb_rsg = config._find_resources(template, "AWS::Route53::RecordSetGroup")
        elb_sgs = config._find_resources(template, "AWS::EC2::SecurityGroup")

        compare(self._resources_to_dict(known_load_balancer_resources),
                self._resources_to_dict(elb_cfg))
        compare(self._resources_to_dict(known_policy_type_resources),
                self._resources_to_dict(elb_pt))
        compare(self._resources_to_dict(known_record_set_resources),
                self._resources_to_dict(elb_rsg))
        compare(self._resources_to_dict(expected_sgs),
                self._resources_to_dict(elb_sgs))
        # Test for outputs
        expected_outputs = {
            "ELBtestdevexternal": {
                "Description": "ELB DNSName",
                "Value": {
                    "Fn::GetAtt": [
                        "ELBtestdevexternal",
                        "DNSName"
                    ]
                }
            },
            "ELBtestdevinternal": {
                "Description": "ELB DNSName",
                "Value": {
                    "Fn::GetAtt": [
                        "ELBtestdevinternal",
                        "DNSName"
                    ]
                }
            }
        }
        actual_outputs = self._resources_to_dict(template.outputs.values())
        compare(expected_outputs, actual_outputs)

    def test_elb_custom_sg(self):

        expected_sgs = {
            'SGName': {
                'Properties': {
                    u'SecurityGroupIngress': [
                        {'ToPort': 443,
                         'IpProtocol': 'tcp',
                         'CidrIp': '1.2.3.4/32',
                         'FromPort': 443},
                    ],
                    'VpcId': {'Ref': 'VPC'},
                    'GroupDescription': 'SGName'
                },
                'Type': u'AWS::EC2::SecurityGroup',
            },
        }

        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')

        # Remove the "test-dev-internal" ELB
        project_config.config['elb'] = [{
            'name': 'test-dev-external',
            'hosted_zone': 'kyrtest.pf.x',
            'scheme': 'internet-facing',
            'listeners': [
                {'LoadBalancerPort': 443,
                 'InstancePort': 443,
                 'Protocol': 'TCP'}
            ],
            'security_groups': {
                'SGName': [
                    {'IpProtocol': 'tcp',
                     'FromPort': 443,
                     'ToPort': 443,
                     'CidrIp': '1.2.3.4/32'},
                ]
            }
        }]

        config = ConfigParser(project_config.config, 'my-stack-name')

        # Create elb resources with template
        template = Template()
        config.elb(template)
        elb_cfg = config._find_resources(template, "AWS::ElasticLoadBalancing::LoadBalancer")
        elb_sgs = config._find_resources(template, "AWS::EC2::SecurityGroup")

        elb_dict = self._resources_to_dict(elb_cfg)
        sgs_dict = self._resources_to_dict(elb_sgs)
        compare(expected_sgs, sgs_dict)

        # elb = [e.values()[0] for e in elb_dict if 'ELBtestdevexternal' in e]
        compare(elb_dict['ELBtestdevexternal']['Properties']['SecurityGroups'],
                [{u'Ref': u'SGName'}])

    @patch('bootstrap_cfn.config.ConfigParser.get_keyname', return_value='default')
    def test_cf_includes(self, get_keyname_mock):
        project_config = ProjectConfig('tests/sample-project.yaml',
                                       'dev',
                                       'tests/sample-project-passwords.yaml')
        project_config.config['includes'] = ['tests/sample-include.json']
        known_outputs = {
            "dbhost": {
                "Description": "RDS Hostname",
                "Value": {"Fn::GetAtt": ["RDSInstance", "Endpoint.Address"]}
            },
            "dbport": {
                "Description": "RDS Port",
                "Value": {"Fn::GetAtt": ["RDSInstance", "Endpoint.Port"]}
            },
            "someoutput": {
                "Description": "For tests",
                "Value": "BLAHBLAH"
            },
            "StaticBucketName": {
                "Description": "S3 bucket name",
                "Value": {"Ref": "StaticBucket"}
            },
            "ELBtestdevexternal": {
                "Description": "ELB DNSName",
                "Value": {"Fn::GetAtt": ["ELBtestdevexternal", "DNSName"]}
            },
            "ELBtestdevinternal": {
                "Description": "ELB DNSName",
                "Value": {"Fn::GetAtt": ["ELBtestdevinternal", "DNSName"]}
            },
            "ElasticacheEngine": {
                "Description": "Elasticache Engine",
                "Value": "redis"
            },
            "ElasticacheReplicationGroupName": {
                "Description": "Elasticache Replication Group Name",
                "Value": {"Ref": "ElasticacheReplicationGroup"}
            }
        }
        config = ConfigParser(project_config.config, 'my-stack-name')
        cfg = json.loads(config.process())
        outputs = cfg['Outputs']
        compare(known_outputs, outputs)

    @patch('bootstrap_cfn.config.ConfigParser.get_keyname', return_value='default')
    def test_process(self, get_keyname_mock):
        """
        This isn't the best test, but we at least check that we have the right
        Resource names returned
        """
        project_config = ProjectConfig(
            'tests/sample-project.yaml',
            'dev',
            'tests/sample-project-passwords.yaml')
        config = ConfigParser(project_config.config, 'my-stack-name')

        cfn_template = json.loads(config.process())

        wanted = [
            "AnotherSG", "AnotherSGRule0", "AttachGateway", "BaseHostLaunchConfig",
            "BaseHostRole", "BaseHostSG", "BaseHostSGRule0", "BaseHostSGRule1", "DNStestdevexternal",
            "DNStestdevinternal", "DatabaseSG", "DefaultSGtestdevexternal",
            "DefaultSGtestdevinternal", "ELBtestdevexternal",
            "ELBtestdevinternal", "ElasticacheReplicationGroup",
            "ElasticacheSG", "ElasticacheSubnetGroup", "InstanceProfile", "InternetGateway",
            "Policytestdevexternal", "Policytestdevinternal", "PublicRoute",
            "PublicRouteTable", "RDSInstance", "RDSSubnetGroup",
            "RolePolicies", "ScalingGroup", "StaticBucket",
            "StaticBucketPolicy",
            "SubnetA", "SubnetARouteTableAssociation",
            "SubnetB", "SubnetBRouteTableAssociation",
            "SubnetC", "SubnetCRouteTableAssociation",
            "VPC",
        ]

        resource_names = cfn_template['Resources'].keys()
        resource_names.sort()
        compare(resource_names, wanted)

        wanted = ["ELBtestdevexternal",
                  "ELBtestdevinternal",
                  "ElasticacheEngine",
                  "ElasticacheReplicationGroupName",
                  "StaticBucketName",
                  "dbhost",
                  "dbport"]
        output_names = cfn_template['Outputs'].keys()
        output_names.sort()
        compare(wanted, output_names)

        mappings = cfn_template['Mappings']
        expected = {
            'AWSRegion2AMI': {'eu-west-1': {'AMI': 'ami-f95ef58a'}},
            'SubnetConfig': {
                'VPC': {
                    'CIDR': '10.0.0.0/16',
                    'SubnetA': '10.0.0.0/20',
                    'SubnetB': '10.0.16.0/20',
                    'SubnetC': '10.0.32.0/20',
                }
            }
        }
        compare(mappings, expected)

    @patch('bootstrap_cfn.config.ConfigParser.get_keyname', return_value='default')
    def test_process_with_vpc_config(self, get_keyname_mock):
        """
        This isn't the best test, but we at least check that we have the right
        Resource names returned
        """
        project_config = ProjectConfig(
            'tests/sample-project.yaml',
            'dev',
            'tests/sample-project-passwords.yaml')
        project_config.config['vpc'] = {
            'CIDR': '172.22.0.0/16',
            'SubnetA': '172.22.1.0/24',
            'SubnetB': '172.22.2.0/24',
            'SubnetC': '172.22.3.0/24',
        }
        config = ConfigParser(project_config.config, 'my-stack-name')

        cfn_template = json.loads(config.process())

        wanted = [
            "AnotherSG", "AnotherSGRule0", "AttachGateway", "BaseHostLaunchConfig",
            "BaseHostRole", "BaseHostSG", "BaseHostSGRule0", "BaseHostSGRule1", "DNStestdevexternal",
            "DNStestdevinternal", "DatabaseSG", "DefaultSGtestdevexternal",
            "DefaultSGtestdevinternal", "ELBtestdevexternal",
            "ELBtestdevinternal", "ElasticacheReplicationGroup",
            "ElasticacheSG", "ElasticacheSubnetGroup", "InstanceProfile", "InternetGateway",
            "Policytestdevexternal", "Policytestdevinternal", "PublicRoute",
            "PublicRouteTable", "RDSInstance", "RDSSubnetGroup",
            "RolePolicies", "ScalingGroup", "StaticBucket",
            "StaticBucketPolicy",
            "SubnetA", "SubnetARouteTableAssociation",
            "SubnetB", "SubnetBRouteTableAssociation",
            "SubnetC", "SubnetCRouteTableAssociation",
            "VPC"
        ]

        resource_names = cfn_template['Resources'].keys()
        resource_names.sort()
        compare(resource_names, wanted)

        wanted = ["ELBtestdevexternal",
                  "ELBtestdevinternal",
                  "ElasticacheEngine",
                  "ElasticacheReplicationGroupName",
                  "StaticBucketName",
                  "dbhost",
                  "dbport"]
        output_names = cfn_template['Outputs'].keys()
        output_names.sort()
        compare(wanted, output_names)

        mappings = cfn_template['Mappings']
        expected = {
            'AWSRegion2AMI': {'eu-west-1': {'AMI': 'ami-f95ef58a'}},
            'SubnetConfig': {
                'VPC': {
                    'CIDR': '172.22.0.0/16',
                    'SubnetA': '172.22.1.0/24',
                    'SubnetB': '172.22.2.0/24',
                    'SubnetC': '172.22.3.0/24',
                }
            }
        }
        compare(mappings, expected)

    @patch('bootstrap_cfn.config.ConfigParser.get_keyname', return_value='default')
    def test_process_no_elbs_no_rds(self, get_keyname_mock):
        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        # Assuming there's no ELB defined
        project_config.config.pop('elb')
        project_config.config.pop('rds')
        config = ConfigParser(project_config.config, 'my-stack-name')
        config.process()

    @patch('bootstrap_cfn.config.ConfigParser.get_keyname', return_value='default')
    def test_ami_overrides_os_default(self, get_keyname_mock):
        self.maxDiff = None
        project_config = ProjectConfig(
                'tests/sample-project.yaml',
                'dev',
                'tests/sample-project-passwords.yaml')

        project_config.config['ec2']['ami'] = 'ami-0000000000'
        project_config.config['ec2']['os'] = 'windows2012'
        config = ConfigParser(project_config.config, 'my-stack-name')
        cfn_template = json.loads(config.process())
        compare(cfn_template['Mappings']['AWSRegion2AMI'], {'eu-west-1': {'AMI': 'ami-0000000000'}})

    def test_elb_missing_cert(self):

        self.maxDiff = None
        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        # Ugh. Fixtures please?
        project_config.config.pop('ssl')
        project_config.config['elb'] = [{
            'name': 'docker-registry.service',
            'hosted_zone': 'kyrtest.foo.bar.',
            'certificate_name': 'my-cert',
            'scheme': 'internet-facing',
            'listeners': [
                {'LoadBalancerPort': 80,
                 'InstancePort': 80,
                 'Protocol': 'TCP'
                 },
                {'LoadBalancerPort': 443,
                 'InstancePort': 443,
                 'Protocol': 'HTTPS'
                 },
            ],
        }]
        config = ConfigParser(project_config.config, 'my-stack-name')
        with self.assertRaises(errors.CfnConfigError):
            config.elb(Template())

    def test_elb_missing_cert_name(self):

        self.maxDiff = None
        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        # Ugh. Fixtures please?
        project_config.config['elb'] = [{
            'name': 'docker-registry.service',
            'hosted_zone': 'kyrtest.foo.bar.',
            'scheme': 'internet-facing',
            'listeners': [
                {'LoadBalancerPort': 80,
                 'InstancePort': 80,
                 'Protocol': 'TCP'
                 },
                {'LoadBalancerPort': 443,
                 'InstancePort': 443,
                 'Protocol': 'HTTPS'
                 },
            ],
        }]
        config = ConfigParser(project_config.config, 'my-stack-name')
        with self.assertRaises(errors.CfnConfigError):
            config.elb(Template())

    def test_elb_with_ssl(self):

        self.maxDiff = None
        DNSdockerregistryservice = RecordSetGroup(
            "DNSdockerregistryservice",
            Comment="Zone apex alias targeted to ElasticLoadBalancer.",
            HostedZoneName="kyrtest.foo.bar.",
            RecordSets=[
                {"Type": "A",
                 "AliasTarget": {
                     "HostedZoneId": GetAtt("ELBdockerregistryservice",
                                            "CanonicalHostedZoneNameID"),
                     "DNSName": GetAtt("ELBdockerregistryservice", "DNSName")
                 },
                 "Name": "docker-registry.service-name.kyrtest.foo.bar."
                 }
            ],
        )

        ELBdockerregistryservice = LoadBalancer(
            "ELBdockerregistryservice",
            ConnectionDrainingPolicy=ConnectionDrainingPolicy(
                Enabled=True,
                Timeout=120,
            ),
            Subnets=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")],
            Listeners=[
                {"InstancePort": 80, "LoadBalancerPort": 80, "Protocol": "TCP"},
                {"InstancePort": 443, "SSLCertificateId": Join(
                    "", ["arn:aws:iam::", Ref("AWS::AccountId"),
                         ":server-certificate/", "my-cert-my-stack-name"]),
                 "LoadBalancerPort": 443, "Protocol": "HTTPS",
                 "PolicyNames": ["PinDownSSLNegotiationPolicy201505"]}],
            SecurityGroups=[Ref("DefaultSGdockerregistryservice")],
            Scheme="internet-facing",
            Policies=[
                Policy(
                    Attributes=[{'Name': "Reference-Security-Policy", 'Value': "ELBSecurityPolicy-2015-05"}],
                    PolicyType='SSLNegotiationPolicyType',
                    PolicyName='PinDownSSLNegotiationPolicy201505'
                )
            ],
        )

        Policydockerregistryservice = PolicyType(
            "Policydockerregistryservice",
            PolicyName="dockerregistryserviceBaseHost",
            PolicyDocument={
                "Statement": [
                    {
                        "Action": [
                            "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                            "elasticloadbalancing:RegisterInstancesWithLoadBalancer"
                        ],
                        "Resource": [
                            Join("", ["arn:aws:elasticloadbalancing:",
                                      Ref("AWS::Region"), ":",
                                      Ref("AWS::AccountId"),
                                      ":loadbalancer/",
                                      {"Ref": "ELBdockerregistryservice"}
                                      ]
                                 )
                        ],
                        "Effect": "Allow"
                    }
                ]
            },
            Roles=[Ref("BaseHostRole")],
        )
        DefaultSGdockerregistryservice = SecurityGroup(
            "DefaultSGdockerregistryservice",
            GroupDescription="DefaultELBSecurityGroup",
            SecurityGroupIngress=[{"CidrIp": "0.0.0.0/0",
                                   "FromPort": 443,
                                   "IpProtocol": "tcp",
                                   "ToPort": 443},
                                  {"CidrIp": "0.0.0.0/0",
                                   "FromPort": 80,
                                   "IpProtocol": "tcp",
                                   "ToPort": 80}
                                  ],
            VpcId=Ref("VPC")
        )
        known = [DNSdockerregistryservice, ELBdockerregistryservice,
                 Policydockerregistryservice, DefaultSGdockerregistryservice]

        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        # Ugh. Fixtures please?
        project_config.config['elb'] = [{
            'name': 'docker-registry.service',
            'hosted_zone': 'kyrtest.foo.bar.',
            'scheme': 'internet-facing',
            'certificate_name': 'my-cert',
            'listeners': [
                {'LoadBalancerPort': 80,
                 'InstancePort': 80,
                 'Protocol': 'TCP'
                 },
                {'LoadBalancerPort': 443,
                 'InstancePort': 443,
                 'Protocol': 'HTTPS'
                 },
            ],
        }]
        config = ConfigParser(project_config.config, 'my-stack-name')

        # Create elb resources with template
        template = Template()
        config.elb(template)
        elb_cfg = template.resources.values()

        compare(self._resources_to_dict(known),
                self._resources_to_dict(elb_cfg))

    def test_elb_with_healthcheck(self):
        self.maxDiff = None

        DNSdockerregistryservice = RecordSetGroup(
            "DNSdockerregistryservice",
            Comment="Zone apex alias targeted to ElasticLoadBalancer.",
            HostedZoneName="kyrtest.foo.bar.",
            RecordSets=[
                {
                    "Type": "A",
                    "AliasTarget": {
                        "HostedZoneId": GetAtt("ELBdockerregistryservice",
                                               "CanonicalHostedZoneNameID"),
                        "DNSName": GetAtt("ELBdockerregistryservice", "DNSName")
                    },
                    "Name": "docker-registry.service-name.kyrtest.foo.bar."
                }
            ],
        )

        ELBdockerregistryservice = LoadBalancer(
            "ELBdockerregistryservice",
            ConnectionDrainingPolicy=ConnectionDrainingPolicy(
                Enabled=True,
                Timeout=120,
            ),
            Subnets=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")],
            HealthCheck=HealthCheck(
                HealthyThreshold=10,
                Interval=2,
                Target="HTTPS:80/blah",
                Timeout=5,
                UnhealthyThreshold=2,
            ),
            Listeners=[{"InstancePort": 80,
                        "LoadBalancerPort": 80,
                        "Protocol": "TCP"},
                       {"InstancePort": 443,
                        "LoadBalancerPort": 443,
                        "Protocol": "TCP"}
                       ],
            SecurityGroups=[Ref("DefaultSGdockerregistryservice")],
            Scheme="internet-facing",
            Policies=[
                Policy(
                    Attributes=[{'Name': "Reference-Security-Policy", 'Value': "ELBSecurityPolicy-2015-05"}],
                    PolicyType='SSLNegotiationPolicyType',
                    PolicyName='PinDownSSLNegotiationPolicy201505'
                )
            ],
        )

        Policydockerregistryservice = PolicyType(
            "Policydockerregistryservice",
            PolicyName="dockerregistryserviceBaseHost",
            PolicyDocument={
                "Statement": [
                    {
                        "Action":
                            ["elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                             "elasticloadbalancing:RegisterInstancesWithLoadBalancer"],
                        "Resource": [
                            Join("", ["arn:aws:elasticloadbalancing:",
                                      Ref("AWS::Region"), ":",
                                      Ref("AWS::AccountId"),
                                      ":loadbalancer/",
                                      {"Ref": "ELBdockerregistryservice"}]
                                 )],
                        "Effect": "Allow"
                    }
                ]

            },
            Roles=[Ref("BaseHostRole")],
        )
        DefaultSGdockerregistryservice = SecurityGroup(
            "DefaultSGdockerregistryservice",
            GroupDescription="DefaultELBSecurityGroup",
            SecurityGroupIngress=[{"CidrIp": "0.0.0.0/0",
                                   "FromPort": 443,
                                   "IpProtocol": "tcp",
                                   "ToPort": 443},
                                  {"CidrIp": "0.0.0.0/0",
                                   "FromPort": 80,
                                   "IpProtocol": "tcp",
                                   "ToPort": 80}
                                  ],
            VpcId=Ref("VPC")
        )

        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        project_config.config['elb'] = [
            {
                'name': 'docker-registry.service',
                'hosted_zone': 'kyrtest.foo.bar.',
                'scheme': 'internet-facing',
                'listeners': [
                    {'LoadBalancerPort': 80,
                     'InstancePort': 80,
                     'Protocol': 'TCP'
                     },
                    {'LoadBalancerPort': 443,
                     'InstancePort': 443,
                     'Protocol': 'TCP'
                     },
                ],
                'health_check': {
                    'HealthyThreshold': 10,
                    'Interval': 2,
                    'Target': 'HTTPS:80/blah',
                    'Timeout': 5,
                    'UnhealthyThreshold': 2
                }
            }
        ]
        config = ConfigParser(project_config.config, 'my-stack-name')

        # Create elb resources with template
        template = Template()
        config.elb(template)
        elb_cfg = template.resources.values()

        known = [DNSdockerregistryservice, ELBdockerregistryservice,
                 Policydockerregistryservice, DefaultSGdockerregistryservice]
        compare(self._resources_to_dict(known),
                self._resources_to_dict(elb_cfg))

    def test_elb_with_reserved_chars(self):
        ELBdevdockerregistryservice = LoadBalancer(
            "ELBdevdockerregistryservice",
            ConnectionDrainingPolicy=ConnectionDrainingPolicy(
                Enabled=True,
                Timeout=120,
            ),
            Subnets=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")],
            Listeners=[
                {"InstancePort": 80,
                 "LoadBalancerPort": 80,
                 "Protocol": "TCP"},
                {"InstancePort": 443,
                 "LoadBalancerPort": 443,
                 "Protocol": "TCP"
                 }
            ],
            SecurityGroups=[Ref("DefaultSGdevdockerregistryservice")],
            Scheme="internet-facing",
            Policies=[
                Policy(
                    Attributes=[{'Name': "Reference-Security-Policy", 'Value': "ELBSecurityPolicy-2015-05"}],
                    PolicyType='SSLNegotiationPolicyType',
                    PolicyName='PinDownSSLNegotiationPolicy201505'
                )
            ],
        )

        DNSdevdockerregistryservice = RecordSetGroup(
            "DNSdevdockerregistryservice",
            Comment="Zone apex alias targeted to ElasticLoadBalancer.",
            HostedZoneName="kyrtest.foo.bar.",
            RecordSets=[
                {"Type": "A",
                 "AliasTarget": {
                     "HostedZoneId":
                         GetAtt(ELBdevdockerregistryservice,
                                "CanonicalHostedZoneNameID"),
                     "DNSName": GetAtt(ELBdevdockerregistryservice,
                                       "DNSName")
                 },
                 "Name": "dev_docker-registry.service-name.kyrtest.foo.bar."
                 }
            ],
        )

        Policydevdockerregistryservice = PolicyType(
            "Policydevdockerregistryservice",
            PolicyName="devdockerregistryserviceBaseHost",
            PolicyDocument={
                "Statement":
                    [
                        {
                            "Action": [
                                "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                                "elasticloadbalancing:RegisterInstancesWithLoadBalancer"],
                            "Resource": [
                                Join("",
                                     ["arn:aws:elasticloadbalancing:",
                                      Ref("AWS::Region"), ":",
                                      Ref("AWS::AccountId"),
                                      ":loadbalancer/",
                                      {"Ref": "ELBdevdockerregistryservice"}]
                                     )
                            ],
                            "Effect": "Allow"
                        }
                    ]
            },
            Roles=[Ref("BaseHostRole")],
        )
        DefaultSGdevdockerregistryservice = SecurityGroup(
            "DefaultSGdevdockerregistryservice",
            GroupDescription="DefaultELBSecurityGroup",
            SecurityGroupIngress=[{"CidrIp": "0.0.0.0/0",
                                   "FromPort": 443,
                                   "IpProtocol": "tcp",
                                   "ToPort": 443},
                                  {"CidrIp": "0.0.0.0/0",
                                   "FromPort": 80,
                                   "IpProtocol": "tcp",
                                   "ToPort": 80}
                                  ],
            VpcId=Ref("VPC")
        )

        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        # Ugh. Fixtures please?
        project_config.config['elb'] = [{
            'name': 'dev_docker-registry.service',
            'hosted_zone': 'kyrtest.foo.bar.',
            'scheme': 'internet-facing',
            'listeners': [
                {'LoadBalancerPort': 80,
                 'InstancePort': 80,
                 'Protocol': 'TCP'
                 },
                {'LoadBalancerPort': 443,
                 'InstancePort': 443,
                 'Protocol': 'TCP'
                 },
            ],
        }]
        config = ConfigParser(project_config.config, 'my-stack-name')

        # Create elb resources with template
        template = Template()
        config.elb(template)
        elb_cfg = template.resources.values()

        known = [DNSdevdockerregistryservice, ELBdevdockerregistryservice,
                 Policydevdockerregistryservice, DefaultSGdevdockerregistryservice]
        compare(self._resources_to_dict(known),
                self._resources_to_dict(elb_cfg))

    @patch('bootstrap_cfn.config.ConfigParser.get_keyname', return_value='default')
    def test_ec2(self, get_keyname_mock):

        self.maxDiff = None

        tags = [
            ('Name', {u'Fn::Join': [u'', [{u'Ref': u'AWS::StackName'}, u'-', u'ec2']]}),
            ('Apps', 'test'),
            ('Role', 'docker'),
        ]
        ScalingGroup = AutoScalingGroup(
            "ScalingGroup",
            DesiredCapacity=1,
            Tags=[Tag(k, v, True) for (k, v) in tags],
            MinSize=0,
            MaxSize=3,
            VPCZoneIdentifier=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")],
            LaunchConfigurationName=Ref("BaseHostLaunchConfig"),
            AvailabilityZones=GetAZs(""),
            HealthCheckGracePeriod=300,
            HealthCheckType='EC2',
            DependsOn=['AttachGateway']
        )

        BaseHostSG = SecurityGroup(
            "BaseHostSG",
            VpcId=Ref("VPC"),
            GroupDescription="BaseHost Security Group",
        )
        BaseHostSGRule0 = SecurityGroupIngress(
            "BaseHostSGRule0",
            ToPort=22,
            FromPort=22,
            CidrIp="0.0.0.0/0",
            IpProtocol="tcp",
            GroupId=Ref(BaseHostSG),
        )
        BaseHostSGRule1 = SecurityGroupIngress(
            "BaseHostSGRule1",
            ToPort=80,
            FromPort=80,
            CidrIp="0.0.0.0/0",
            IpProtocol="tcp",
            GroupId=Ref(BaseHostSG),
        )

        BaseHostLaunchConfig = LaunchConfiguration(
            "BaseHostLaunchConfig",
            ImageId=FindInMap("AWSRegion2AMI", Ref("AWS::Region"), "AMI"),
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {"VolumeSize": 10, "VolumeType": "standard"}
                },
                {
                    "DeviceName": "/dev/sdf",
                    "Ebs": {"VolumeSize": 10, "VolumeType": "gp2"}
                },
                {
                    "DeviceName": "/dev/sdg",
                    "Ebs": {"VolumeSize": 20, "VolumeType": "io1", "Iops": 100}
                }
            ],
            KeyName="default",
            SecurityGroups=[Ref(BaseHostSG), Ref("AnotherSG")],
            IamInstanceProfile=Ref("InstanceProfile"),
            InstanceType="t2.micro",
            AssociatePublicIpAddress="true",
        )

        AnotherSG = SecurityGroup(
            "AnotherSG",
            VpcId=Ref("VPC"),
            GroupDescription="BaseHost Security Group",
        )
        AnotherSGRule0 = SecurityGroupIngress(
            "AnotherSGRule0",
            ToPort=443,
            FromPort=443,
            SourceSecurityGroupName=Ref(BaseHostSG),
            IpProtocol="tcp",
            GroupId=Ref(AnotherSG),
        )
        known = [AnotherSG, AnotherSGRule0, BaseHostLaunchConfig, BaseHostSG, BaseHostSGRule0, BaseHostSGRule1, ScalingGroup]
        config = ConfigParser(
            ProjectConfig(
                'tests/sample-project.yaml',
                'dev').config, 'my-stack-name')

        with patch.object(config, 'get_ec2_userdata', return_value=None):
            ec2_json = self._resources_to_dict(config.ec2())

        compare(self._resources_to_dict(known), ec2_json)

    @patch('bootstrap_cfn.config.ConfigParser.get_keyname', return_value='default')
    # We just want to test that when we have userdata we return the right LaunchConfig.
    def test_launchconfig_userdata(self, get_keyname_mock):
        config = ConfigParser(
            ProjectConfig('tests/sample-project.yaml', 'dev').config,
            'my-stack-name')
        BaseHostLaunchConfig = LaunchConfiguration(
            "BaseHostLaunchConfig",
            ImageId=FindInMap("AWSRegion2AMI", Ref("AWS::Region"), "AMI"),
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {"VolumeSize": 10, "VolumeType": "standard"}
                },
                {
                    "DeviceName": "/dev/sdf",
                    "Ebs": {"VolumeSize": 10, "VolumeType": "gp2"}
                },
                {
                    "DeviceName": "/dev/sdg",
                    "Ebs": {"VolumeSize": 20, "VolumeType": "io1", "Iops": 100}
                }
            ],
            KeyName="default",
            SecurityGroups=[Ref("BaseHostSG"), Ref("AnotherSG")],
            IamInstanceProfile=Ref("InstanceProfile"),
            InstanceType="t2.micro",
            AssociatePublicIpAddress="true",
            UserData=Base64("Mock String"),
        )

        with patch.object(config, "get_ec2_userdata", return_value="Mock String"):
            with patch.object(mime_packer, "pack", side_effect=lambda x: x):
                ec2_json = self._resources_to_dict(config.ec2())
                expected = self._resources_to_dict([BaseHostLaunchConfig])
                compare(ec2_json['BaseHostLaunchConfig'], expected['BaseHostLaunchConfig'])

    def test_get_ec2_userdata(self):
        data = {
            'ec2': {
                'cloud_config': {'some': 'dict'}
            }
        }
        config = ConfigParser(data, environment="env", application="test", stack_name="my-stack")
        with patch.object(config, 'get_hostname_boothook', return_value={"content": "sentinel"}) as mock_boothook:
            user_data_parts = config.get_ec2_userdata()
            mock_boothook.assert_called_once_with(data['ec2'])
            # We have linux, so we put package update data in first
            compare(user_data_parts[0]['content'], '{package_reboot_if_required: true, package_update: true, package_upgrade: true}\n')
            compare(user_data_parts[1]['content'], 'sentinel')
            compare(yaml.load(user_data_parts[2]['content']), data['ec2']['cloud_config'])

    def test_get_ec2_userdata_no_cloud_config(self):
        # If there is no cloud config we should get a default
        # 'manage_etc_hosts' because of the default hostname pattern
        data = {
            'ec2': {
            }
        }
        config = ConfigParser(data, environment="env", application="test", stack_name="my-stack")
        with patch.object(config, 'get_hostname_boothook', return_value={"content": "sentinel"}) as mock_boothook:
            user_data_parts = config.get_ec2_userdata()
            mock_boothook.assert_called_once_with(data['ec2'])
            # We have linux, so we put package update data in first
            compare(user_data_parts[0]['content'], '{package_reboot_if_required: true, package_update: true, package_upgrade: true}\n')
            compare(user_data_parts[1]['content'], 'sentinel')
            compare(yaml.load(user_data_parts[2]['content']), {'manage_etc_hosts': True})

    def test_get_hostname_boothook(self):
        config = ConfigParser({}, environment="env", application="test", stack_name="my-stack")

        cfg = {
            # Longer than people would use but tests all interpolations.
            'hostname_pattern': '{instance_id}.{tags[Role]}.{environment}.{application}.{stack_name}',
            'tags': {'Role': 'docker'},
        }
        part = config.get_hostname_boothook(cfg)
        expected = {
            'content': ('#!/bin/sh\n'
                        '[ -e /etc/cloud/cloud.cfg.d/99_hostname.cfg ] || '
                        'echo "hostname: ${INSTANCE_ID}.docker.env.test.my-stack" > /etc/cloud/cloud.cfg.d/99_hostname.cfg\n'),
            'mime_type': 'text/cloud-boothook',
        }
        compare(part, expected)

    def test_get_hostname_boothook_default(self):
        config = ConfigParser({}, environment="env", application="test", stack_name="my-stack")

        cfg = {
            'tags': {'Role': 'docker'},
        }
        part = config.get_hostname_boothook(cfg)
        expected = {
            'content': ('#!/bin/sh\n'
                        '[ -e /etc/cloud/cloud.cfg.d/99_hostname.cfg ] || '
                        'echo "hostname: ${INSTANCE_ID}.env.test" > /etc/cloud/cloud.cfg.d/99_hostname.cfg\n'),
            'mime_type': 'text/cloud-boothook',
        }
        compare(part, expected)

    def test_get_hostname_boothook_nonoe(self):
        config = ConfigParser({}, environment="env", application="test", stack_name="my-stack")

        cfg = {
            'hostname_pattern': None,
            'tags': {'Role': 'docker'},
        }
        part = config.get_hostname_boothook(cfg)
        expected = None
        compare(part, expected)

    @patch('sys.stderr', StringIO())
    def test_get_hostname_boothook_error(self):
        config = ConfigParser({}, environment="env", application="test", stack_name="my-stack")

        cfg = {
            # Longer than people would use but tests all interpolations.
            'hostname_pattern': '{tags[Fake]}',
            'tags': {'Role': 'docker'},
        }

        with self.assertRaisesRegexp(errors.CfnHostnamePatternError, r"Error interpolating hostname_pattern .*\bFake"):
            config.get_hostname_boothook(cfg)
            self.fail()

        cfg['hostname_pattern'] = '{non_existent}'
        with self.assertRaisesRegexp(errors.CfnHostnamePatternError, r"Error interpolating hostname_pattern .*\bnon_existent"):
            config.get_hostname_boothook(cfg)
            self.fail()

    @patch('bootstrap_cfn.config.ConfigParser.get_keyname', return_value='default')
    def test_ec2_with_no_block_device_specified(self, get_keyname_mock):
        project_config = ProjectConfig('tests/sample-project.yaml', 'dev')
        project_config.config['ec2'].pop('block_devices')
        config = ConfigParser(project_config.config, 'my-stack-name')
        ec2_dict = self._resources_to_dict(config.ec2())
        config_output = ec2_dict['BaseHostLaunchConfig'][
            'Properties']['BlockDeviceMappings']
        known = [{'DeviceName': '/dev/sda1', 'Ebs': {'VolumeSize': 20}}]
        self.assertEquals(known, config_output)

if __name__ == '__main__':
    unittest.main()
