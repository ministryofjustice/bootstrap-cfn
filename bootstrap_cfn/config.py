import json
import logging
import os
import sys
import textwrap

from troposphere import Base64, FindInMap, GetAZs, GetAtt, Join, Output, Ref, Tags, Template
from troposphere.autoscaling import AutoScalingGroup, BlockDeviceMapping, \
    EBSBlockDevice, LaunchConfiguration, Tag
from troposphere.ec2 import InternetGateway, Route, RouteTable, SecurityGroup, \
    SecurityGroupIngress, Subnet, SubnetRouteTableAssociation, VPC, \
    VPCGatewayAttachment
from troposphere.elasticache import ReplicationGroup, SubnetGroup

from troposphere.elasticloadbalancing import ConnectionDrainingPolicy, \
    HealthCheck, LoadBalancer, Policy
from troposphere.iam import InstanceProfile, PolicyType, Role
from troposphere.rds import DBInstance, DBSubnetGroup
from troposphere.route53 import AliasTarget, RecordSet, RecordSetGroup
from troposphere.s3 import Bucket, BucketPolicy

import yaml

from bootstrap_cfn import errors, mime_packer, utils


class ProjectConfig:

    config = None

    def __init__(self,
                 config,
                 environment,
                 passwords=None,
                 defaults=os.path.join(os.path.dirname(__file__), 'config_defaults.yaml')):
        try:
            self.config = {}
            # Load all the necessary config files and defaults
            config_defaults = self.load_yaml(defaults).get(environment,
                                                           self.load_yaml(defaults)['default'])
            user_config = self.load_yaml(config)[environment]
            passwords_config = {}
            if passwords:
                passwords_config = self.load_yaml(passwords).get(environment, {})

            # Validate all the settings we have loaded in
            logging.info('bootstrap-cfn:: Validating default settings for environment %s in file %s'
                         % (environment, defaults))
            self.validate_configuration_settings(config_defaults)
            logging.info('bootstrap-cfn:: Validating user settings for environment %s in file %s'
                         % (environment, config))
            self.validate_configuration_settings(user_config)
            logging.info('bootstrap-cfn:: Validating passwords settings for environment %s in file %s'
                         % (environment, passwords))
            self.validate_configuration_settings(passwords_config)

            # Collect together all the config keys the user has specified
            all_user_config_keys = set(user_config.keys()) | set(passwords_config.keys())

            # Only set configuration settings where we have specified that component in the user config
            # This means we only get non-required components RDS, elasticache, etc if we have requested them
            for config_key in all_user_config_keys:
                # we're going to merge in order of,
                # defaults <- user_config <- secrets_config

                # Catch badly formatted yaml where we get NoneType values,
                # merging in these will overwrite all the other config
                self.config[config_key] = config_defaults.get(config_key, {})
                # Overwrite defaults with user_config values
                self.config[config_key] = utils.dict_merge(self.config[config_key],
                                                           user_config.get(config_key, {}))
                # Overwrite user config with password config values
                self.config[config_key] = utils.dict_merge(self.config[config_key],
                                                           passwords_config.get(config_key, {}))
        except KeyError:
            raise errors.BootstrapCfnError("Environment " + environment + " not found")

    @staticmethod
    def load_yaml(fp):
        if os.path.exists(fp):
            return yaml.load(open(fp).read())

    @staticmethod
    def validate_configuration_settings(configuration_settings):
        """
        Run some sanity checks on the configuration settings we're going to use

        Args:
            config: The settings object we want to validate

        Raises:
            CfnConfigError
        """
        # Basic settings checks
        # settings should be a dictionary
        if not isinstance(configuration_settings, dict):
            raise errors.CfnConfigError("Configuration settings are not in dictionary format")

        for key, value in configuration_settings.iteritems():
            # No base keys should have a None value
            if value is None:
                raise errors.CfnConfigError("Configuration key value %s is None."
                                            % (key))


class ConfigParser(object):

    config = {}

    def __init__(self, data, stack_name, environment=None, application=None):
        self.stack_name = stack_name
        self.data = data

        # Some things possibly used in user data templates
        self.environment = environment
        self.application = application

    def process(self):
        template = self.base_template()

        vpc = self.vpc()
        map(template.add_resource, vpc)

        iam = self.iam()
        map(template.add_resource, iam)

        ec2 = self.ec2()
        map(template.add_resource, ec2)

        if 'elb' in self.data:
            self.elb(template)

        if 'rds' in self.data:
            self.rds(template)

        if 'elasticache' in self.data:
            self.elasticache(template)

        if 's3' in self.data:
            self.s3(template)

        template = json.loads(template.to_json())
        if 'includes' in self.data:
            for inc_path in self.data['includes']:
                inc = json.load(open(inc_path))
                template = utils.dict_merge(template, inc)
        return json.dumps(
            template, sort_keys=True, indent=4, separators=(',', ': '))

    def base_template(self):
        from bootstrap_cfn import vpc
        t = Template()

        # Get the OS specific data
        os_data = self._get_os_data()
        t.add_mapping("AWSRegion2AMI", {
            os_data.get('region'): {"AMI": os_data.get('ami')},
        })

        if 'vpc' in self.data:
            logging.info('bootstrap-cfn::base_template: Using configuration VPC address settings')
            vpc_data = self.data.get('vpc', {})
            vpc_cidr = vpc_data.get('CIDR', '10.0.0.0/16')
            subneta_cidr = vpc_data.get('SubnetA', '10.0.0.0/20')
            subnetb_cidr = vpc_data.get('SubnetB', '10.0.16.0/20')
            subnetc_cidr = vpc_data.get('SubnetC', '10.0.32.0/20')
            t.add_mapping("SubnetConfig", {
                "VPC": {
                    "CIDR": vpc_cidr,
                    "SubnetA": subneta_cidr,
                    "SubnetB": subnetb_cidr,
                    "SubnetC": subnetc_cidr
                }
            })
        else:
            default_vpc_cidr_prefix = 24
            default_vpc_subnet_prefix = 28
            default_vpc_subnet_count = 3

            # Try to get random CIDR
            available_cidr_block, subnet_cidr_blocks = (
                vpc.get_available_cidr_block(
                    default_vpc_cidr_prefix,
                    subnet_prefix=default_vpc_subnet_prefix)
            )
            if available_cidr_block and len(subnet_cidr_blocks) > (default_vpc_subnet_count - 1):
                logging.info('bootstrap-cfn::base_template: Using dynamic VPC address settings')
                vpc_cidr = available_cidr_block
                subneta_cidr = subnet_cidr_blocks[0]
                subnetb_cidr = subnet_cidr_blocks[1]
                subnetc_cidr = subnet_cidr_blocks[2]
            else:
                # Fallback to default
                logging.info('bootstrap-cfn::base_template: Using static fallback VPC address settings')
                vpc_cidr = "10.0.0.0/24"
                subneta_cidr = "10.0.0.0/20"
                subnetb_cidr = "10.0.16.0/20"
                subnetc_cidr = "10.0.32.0/20"

            t.add_mapping("SubnetConfig", {
                "VPC": {
                    "CIDR": vpc_cidr,
                    "SubnetA": subneta_cidr,
                    "SubnetB": subnetb_cidr,
                    "SubnetC": subnetc_cidr
                }
            })

        return t

    def vpc(self):

        vpc = VPC(
            "VPC",
            InstanceTenancy="default",
            EnableDnsSupport="true",
            CidrBlock=FindInMap("SubnetConfig", "VPC", "CIDR"),
            EnableDnsHostnames="true",
        )

        subnet_a = Subnet(
            "SubnetA",
            VpcId=Ref(vpc),
            AvailabilityZone="eu-west-1a",
            CidrBlock=FindInMap("SubnetConfig", "VPC", "SubnetA"),
            Tags=Tags(
                Application=Ref("AWS::StackId"),
                Network="Public",
            ),
        )

        subnet_b = Subnet(
            "SubnetB",
            VpcId=Ref(vpc),
            AvailabilityZone="eu-west-1b",
            CidrBlock=FindInMap("SubnetConfig", "VPC", "SubnetB"),
            Tags=Tags(
                Application=Ref("AWS::StackId"),
                Network="Public",
            ),
        )

        subnet_c = Subnet(
            "SubnetC",
            VpcId=Ref(vpc),
            AvailabilityZone="eu-west-1c",
            CidrBlock=FindInMap("SubnetConfig", "VPC", "SubnetC"),
            Tags=Tags(
                Application=Ref("AWS::StackId"),
                Network="Public",
            ),
        )

        igw = InternetGateway(
            "InternetGateway",
            Tags=Tags(
                Application=Ref("AWS::StackId"),
                Network="Public",
            ),
        )

        gw_attachment = VPCGatewayAttachment(
            "AttachGateway",
            VpcId=Ref(vpc),
            InternetGatewayId=Ref(igw),
        )

        route_table = RouteTable(
            "PublicRouteTable",
            VpcId=Ref(vpc),
            Tags=Tags(
                Application=Ref("AWS::StackId"),
                Network="Public",
            ),
        )

        public_route = Route(
            "PublicRoute",
            GatewayId=Ref(igw),
            DestinationCidrBlock="0.0.0.0/0",
            RouteTableId=Ref(route_table),
            DependsOn=gw_attachment.title
        )

        subnet_a_route_assoc = SubnetRouteTableAssociation(
            "SubnetRouteTableAssociationA",
            SubnetId=Ref(subnet_a),
            RouteTableId=Ref(route_table),
        )

        subnet_b_route_assoc = SubnetRouteTableAssociation(
            "SubnetRouteTableAssociationB",
            SubnetId=Ref(subnet_b),
            RouteTableId=Ref(route_table),
        )

        subnet_c_route_assoc = SubnetRouteTableAssociation(
            "SubnetRouteTableAssociationC",
            SubnetId=Ref(subnet_c),
            RouteTableId=Ref(route_table),
        )

        resources = [vpc, subnet_a, subnet_b, subnet_c, igw, gw_attachment,
                     public_route, route_table, subnet_a_route_assoc,
                     subnet_b_route_assoc, subnet_c_route_assoc]

        # Hack until we return troposphere objects directly
        # return json.loads(json.dumps(dict((r.title, r) for r in resources), cls=awsencode))
        return resources

    def iam(self):
        role = Role(
            "BaseHostRole",
            Path="/",
            AssumeRolePolicyDocument={
                "Statement": [{
                    "Action": ["sts:AssumeRole"],
                    "Effect": "Allow",
                    "Principal": {"Service": ["ec2.amazonaws.com"]}
                }]
            },
        )
        # Set required policy actions
        policy_actions = [{"Action": ["autoscaling:Describe*"], "Resource": "*", "Effect": "Allow"},
                          {"Action": ["cloudformation:Describe*"], "Resource": "*", "Effect": "Allow"}]

        # Only define policy actions if the components are enabled in the config
        if 'ec2' in self.data:
            policy_actions.append({"Action": ["ec2:Describe*"], "Resource": "*", "Effect": "Allow"})
            policy_actions.append({"Action": ["ec2:CreateTags"], "Resource": "*", "Effect": "Allow"})
        if 'rds' in self.data:
            policy_actions.append({"Action": ["rds:Describe*"], "Resource": "*", "Effect": "Allow"})
        if 'elasticache' in self.data:
            policy_actions.append({"Action": ["elasticloadbalancing:Describe*"], "Resource": "*", "Effect": "Allow"})
            policy_actions.append({"Action": ["elasticache:Describe*"], "Resource": "*", "Effect": "Allow"})
        if 's3' in self.data:
            policy_actions.append({"Action": ["s3:List*"], "Resource": "*", "Effect": "Allow"})

        role_policies = PolicyType(
            "RolePolicies",
            PolicyName="BaseHost",
            PolicyDocument={"Statement": policy_actions},
            Roles=[Ref(role)],
        )
        instance_profile = InstanceProfile(
            "InstanceProfile",
            Path="/",
            Roles=[Ref(role)],
        )

        resources = [role, role_policies, instance_profile]
        # Hack until we return troposphere objects directly
        # return json.loads(json.dumps(dict((r.title, r) for r in resources), cls=awsencode))
        return resources

    def s3(self, template):
        """
        Create an s3 resource configuration from the config file data.
        This will produce Bucket and BucketPolicy resources along with
        the bucket name as output, these are all added to the troposphere
        template.

        Args:
            template:
                The troposphere.Template object
        """
        # As there are no required fields, although we may not have any
        # subkeys we still need to be able to have a parent key 's3:' to
        # signify that we want to create an s3 bucket. In this case we
        # set up an empty (no options set) dictionary
        present_keys = {}
        if isinstance(self.data['s3'], dict):
            present_keys = self.data['s3'].keys()

        # Enable specifying multiple buckets
        if 'buckets' in present_keys:
            bucket_list = self.data['s3'].get('buckets')
            for bucket_config in bucket_list:
                self.create_s3_bucket(bucket_config, template)

        # If the static bucket name is manually set then use that,
        # otherwise use the <stackname>-<logical-resource-name>-<random>
        # default
        bucket = Bucket(
            "StaticBucket",
            AccessControl="BucketOwnerFullControl",
        )
        if 'static-bucket-name' in present_keys:
            bucket.BucketName = self.data['s3']['static-bucket-name']

        # If a policy has been manually set then use it, otherwise set
        # a reasonable default of public 'Get' access
        if 'policy' in present_keys:
            policy = json.loads(open(self.data['s3']['policy']).read())
        else:
            arn = Join("", ["arn:aws:s3:::", Ref(bucket), "/*"])
            policy = {
                'Action': ['s3:GetObject'],
                "Resource": arn,
                'Effect': 'Allow',
                'Principal': '*'}

        bucket_policy = BucketPolicy(
            "StaticBucketPolicy",
            Bucket=Ref(bucket),
            PolicyDocument={"Statement": [policy]},
        )
        # Add the bucket name to the list of cloudformation
        # outputs
        template.add_output(Output(
            "StaticBucketName",
            Description="S3 bucket name",
            Value=Ref(bucket)
        ))

        # Add the resources to the troposphere template
        map(template.add_resource, [bucket, bucket_policy])

    def create_s3_bucket(self, bucket_config, template):
        """
        Create an s3 bucket configuration from config data.
        This will produce Bucket and BucketPolicy resources along with
        the bucket name as output, these are all added to the troposphere
        template.

        Args:
            bucket_config(dictionary): Keyed bucket config settings
            template:
                The troposphere.Template object
        """
        bucket_name = bucket_config.get('name')
        bucket = Bucket(
            bucket_name,
            AccessControl="BucketOwnerFullControl",
        )

        # If a policy has been manually set then use it, otherwise set
        # a reasonable default of public 'Get' access
        if 'policy' in bucket_config:
            policy = json.loads(open(bucket_config['policy']).read())
        else:
            arn = Join("", ["arn:aws:s3:::", Ref(bucket), "/*"])
            policy = {
                'Action': ['s3:DeleteObject', 's3:GetObject', 's3:PutObject'],
                "Resource": arn,
                'Effect': 'Allow',
                'Principal': '*',
                "Condition": {
                    "StringEquals": {
                        "aws:sourceVpc": {"Ref": "VPC"}
                    }
                }
            }
        bucket_policy = BucketPolicy(
            "{}Policy".format(bucket_name),
            Bucket=Ref(bucket),
            PolicyDocument={"Statement": [policy]},
        )
        # Add the bucket name to the list of cloudformation
        # outputs
        template.add_output(Output(
            "{}Policy".format(bucket_name),
            Description="S3 bucket name",
            Value=Ref(bucket)
        ))

        map(template.add_resource, [bucket, bucket_policy])

    def ssl(self):
        return self.data['ssl']

    def rds(self, template):
        """
        Create an RDS resource configuration from the config file data
        and add it to the  troposphere.Template. Outputs for the RDS name,
        host and port are created.

        Args:
            template:
                The troposphere.Template object
        """
        # REQUIRED FIELDS MAPPING
        required_fields = {
            'db-name': 'DBName',
            'db-master-username': 'MasterUsername',
            'db-master-password': 'MasterUserPassword',
        }

        optional_fields = {
            'storage': 'AllocatedStorage',
            'storage-type': 'StorageType',
            'backup-retention-period': 'BackupRetentionPeriod',
            'db-engine': 'Engine',
            'db-engine-version': 'EngineVersion',
            'instance-class': 'DBInstanceClass',
            'multi-az': 'MultiAZ',
            'storage-encrypted': 'StorageEncrypted',
            'identifier': 'DBInstanceIdentifier'
        }

        # LOAD STACK TEMPLATE
        resources = []
        rds_subnet_group = DBSubnetGroup(
            "RDSSubnetGroup",
            SubnetIds=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")],
            DBSubnetGroupDescription="VPC Subnets"
        )
        resources.append(rds_subnet_group)

        database_sg = SecurityGroup(
            "DatabaseSG",
            SecurityGroupIngress=[
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
            ],
            VpcId=Ref("VPC"),
            GroupDescription="SG for EC2 Access to RDS",
        )
        resources.append(database_sg)

        rds_instance = DBInstance(
            "RDSInstance",
            PubliclyAccessible=False,
            AllowMajorVersionUpgrade=False,
            AutoMinorVersionUpgrade=False,
            VPCSecurityGroups=[GetAtt(database_sg, "GroupId")],
            DBSubnetGroupName=Ref(rds_subnet_group),
            DependsOn=database_sg.title
        )
        resources.append(rds_instance)

        # We *cant* specify db-name for SQL Server based RDS instances. :(
        if 'db-engine' in self.data['rds'] and self.data['rds']['db-engine'].startswith("sqlserver"):
            required_fields.pop('db-name')

        # TEST FOR REQUIRED FIELDS AND EXIT IF MISSING ANY
        for yaml_key, rds_prop in required_fields.iteritems():
            if yaml_key not in self.data['rds']:
                print "\n\n[ERROR] Missing RDS fields [%s]" % yaml_key
                sys.exit(1)
            else:
                rds_instance.__setattr__(rds_prop, self.data['rds'][yaml_key])

        for yaml_key, rds_prop in optional_fields.iteritems():
            if yaml_key in self.data['rds']:
                rds_instance.__setattr__(rds_prop, self.data['rds'][yaml_key])

        # Add resources and outputs
        map(template.add_resource, resources)
        template.add_output(Output(
            "dbhost",
            Description="RDS Hostname",
            Value=GetAtt(rds_instance, "Endpoint.Address")
        ))
        template.add_output(Output(
            "dbport",
            Description="RDS Port",
            Value=GetAtt(rds_instance, "Endpoint.Port")
        ))

    def elasticache(self, template):
        """
        Create an elasticache resource configuration from the config file data
        and add it to the  troposphere.Template. Outputs for the elasticache name,
        host and port are created.

        Args:
            template:
                The troposphere.Template object
        """
        # REQUIRED FIELDS MAPPING
        required_fields = {
        }

        optional_fields = {
            'clusters': 'NumCacheClusters',
            'node_type': 'CacheNodeType',
            'port': 'Port',
        }

        # Generate snapshot arns
        seeds = self.data['elasticache'].get('seeds', None)
        snapshot_arns = []
        if seeds:
            # Get s3 seeds
            s3_seeds = seeds.get('s3', [])
            for seed in s3_seeds:
                snapshot_arns.append("arn:aws:s3:::%s" % (seed))

        # LOAD STACK TEMPLATE
        resources = []

        es_sg = SecurityGroup(
            "ElasticacheSG",
            SecurityGroupIngress=[
                {"ToPort": self.data['elasticache']['port'],
                 "FromPort": self.data['elasticache']['port'],
                 "IpProtocol": "tcp",
                 "CidrIp": FindInMap("SubnetConfig", "VPC", "CIDR")}
            ],
            VpcId=Ref("VPC"),
            GroupDescription="SG for EC2 Access to Elasticache",
        )
        resources.append(es_sg)

        es_subnet_group = SubnetGroup(
            'ElasticacheSubnetGroup',
            Description="Elasticache Subnet Group",
            SubnetIds=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")]
        )
        resources.append(es_subnet_group)

        elasticache_replication_group = ReplicationGroup(
            "ElasticacheReplicationGroup",
            ReplicationGroupDescription='Elasticache Replication Group',
            Engine=self.data['elasticache'].get('engine'),
            NumCacheClusters=self.data['elasticache']['clusters'],
            CacheNodeType=self.data['elasticache']['node_type'],
            SecurityGroupIds=[GetAtt(es_sg, "GroupId")],
            CacheSubnetGroupName=Ref(es_subnet_group),
            SnapshotArns=snapshot_arns
        )
        resources.append(elasticache_replication_group)

        # TEST FOR REQUIRED FIELDS AND EXIT IF MISSING ANY
        for yaml_key, prop in required_fields.iteritems():
            if yaml_key not in self.data['elasticache']:
                print "\n\n[ERROR] Missing Elasticache fields [%s]" % yaml_key
                sys.exit(1)
            else:
                elasticache_replication_group.__setattr__(prop, self.data['elasticache'][yaml_key])

        for yaml_key, prop in optional_fields.iteritems():
            if yaml_key in self.data['elasticache']:
                elasticache_replication_group.__setattr__(prop, self.data['elasticache'][yaml_key])

        # Add resources and outputs
        map(template.add_resource, resources)

        template.add_output(Output(
            "ElasticacheReplicationGroupName",
            Description="Elasticache Replication Group Name",
            Value=Ref(elasticache_replication_group)
        ))
        template.add_output(Output(
            "ElasticacheEngine",
            Description="Elasticache Engine",
            Value=self.data['elasticache'].get('engine')
        ))

    def elb(self, template):
        """
        Create an ELB resource configuration from the config file data
        and add them to the troposphere template. Outputs for each ELB's
        DNSName are created.

        Args:
            template:
                The cloudformation template file
        """
        # REQUIRED FIELDS AND MAPPING
        # Note, 'name' field is used internally to help label
        # logical ids, and as part of the DNS record name.
        required_fields = {
            'listeners': 'Listeners',
            'scheme': 'Scheme',
            'name': None,
            'hosted_zone': 'HostedZoneName'
        }

        elb_list = []
        elb_sgs = []
        # COULD HAVE MULTIPLE ELB'S (PUBLIC / PRIVATE etc)
        for elb in self.data['elb']:
            safe_name = elb['name'].replace('-', '').replace('.', '').replace('_', '')
            # TEST FOR REQUIRED FIELDS AND EXIT IF MISSING ANY
            for i in required_fields.keys():
                if i not in elb.keys():
                    print "\n\n[ERROR] Missing ELB fields [%s]" % i
                    sys.exit(1)

            # Collect together all policies
            elb_policies = [
                Policy(
                    Attributes=[{'Name': "Reference-Security-Policy", 'Value': "ELBSecurityPolicy-2015-05"}],
                    PolicyType='SSLNegotiationPolicyType',
                    PolicyName='PinDownSSLNegotiationPolicy201505'
                )]
            for custom_policy_config in elb.get('policies', []):
                custom_policy_name = custom_policy_config.get('name', False)
                custom_policy_type = custom_policy_config.get('type', False)

                if not custom_policy_name:
                    logging.critical("config::elb: Load balancer policy must have a name defined")
                    sys.exit(1)
                if not custom_policy_type:
                    logging.critical("config::elb: Load balancer policy {} must have a type defined".format(custom_policy_name))
                    sys.exit(1)

                custom_policy_attributes = []
                for custom_policy_attribute_config in custom_policy_config.get('attributes', []):
                    for custom_policy_attribute_key, custom_policy_attribute_val in custom_policy_attribute_config.iteritems():
                        custom_policy_attributes_entry = {
                            'Name': custom_policy_attribute_key,
                            'Value': custom_policy_attribute_val
                        }
                        custom_policy_attributes.append(custom_policy_attributes_entry)

                custom_policy = Policy(
                    Attributes=custom_policy_attributes,
                    PolicyType=custom_policy_type,
                    PolicyName=custom_policy_name,
                )
                # Dont set these unless theyre in the config, other CFN will break
                if custom_policy_config.get('instance_ports', False):
                    custom_policy.InstancePorts = custom_policy_config.get('instance_ports')
                if custom_policy_config.get('load_balancer_ports', False):
                    custom_policy.LoadBalancerPorts = custom_policy_config.get('load_balancer_ports')

                elb_policies.append(custom_policy)

            load_balancer = LoadBalancer(
                "ELB" + safe_name,
                Subnets=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")],
                Listeners=elb['listeners'],
                Scheme=elb['scheme'],
                ConnectionDrainingPolicy=ConnectionDrainingPolicy(
                    Enabled=True,
                    Timeout=120,
                ),
                Policies=elb_policies
            )
            if "health_check" in elb:
                load_balancer.HealthCheck = HealthCheck(**elb['health_check'])

            for listener in load_balancer.Listeners:
                if listener['Protocol'] == 'HTTPS':
                    try:
                        cert_name = elb['certificate_name']
                    except KeyError:
                        raise errors.CfnConfigError(
                            "HTTPS listener but no certificate_name specified")
                    try:
                        self.ssl()[cert_name]['cert']
                        self.ssl()[cert_name]['key']
                    except KeyError:
                        raise errors.CfnConfigError(
                            "Couldn't find ssl cert {0} in config file".format(cert_name))

                    listener["SSLCertificateId"] = Join("", [
                        "arn:aws:iam::",
                        Ref("AWS::AccountId"),
                        ":server-certificate/",
                        "{0}-{1}".format(cert_name, self.stack_name)]
                    )
                    # if not present, add the default cipher policy
                    if 'PolicyNames' not in listener:
                        logging.debug(
                            "ELB Listener for port 443 has no SSL Policy. " +
                            "Using default ELBSecurityPolicy-2015-05")
                        listener['PolicyNames'] = ['PinDownSSLNegotiationPolicy201505']
                """
                # Get all the listeners policy names and setup the policies they refer to
                for policy_name in listener.get('PolicyNames', []):
                    matched_policies = [custom_policy for custom_policy in elb_policies
                                        if custom_policy.PolicyName == policy_name]
                    assert(len(matched_policies) == 1)
                    matched_policy = matched_policies[0]
                    # Get the current ports defined in the troposphere policies config and append
                    # the listers ports
                    updated_instance_ports = matched_policy.properties.get('InstancePorts', [])
                    updated_instance_ports.append("{}".format(listener['InstancePort']))
                    matched_policy.properties['InstancePorts'] = updated_instance_ports
                    updated_instance_ports = matched_policy.properties.get('LoadBalancerPorts', [])
                    updated_instance_ports.append("{}".format(listener['LoadBalancerPort']))
                    matched_policy.properties['LoadBalancerPorts'] = updated_instance_ports
                """
            elb_list.append(load_balancer)

            dns_record = RecordSetGroup(
                "DNS" + safe_name,
                HostedZoneName=elb['hosted_zone'],
                Comment="Zone apex alias targeted to ElasticLoadBalancer.",
                RecordSets=[
                    RecordSet(
                        "TitleIsIgnoredForThisResource",
                        Name="%s.%s" % (elb['name'], elb['hosted_zone']),
                        Type="A",
                        AliasTarget=AliasTarget(
                            GetAtt(load_balancer, "CanonicalHostedZoneNameID"),
                            GetAtt(load_balancer, "DNSName"),
                        ),
                    ),
                ]
            )
            elb_list.append(dns_record)

            elb_role_policies = PolicyType(
                "Policy" + safe_name,
                PolicyName=safe_name + "BaseHost",
                PolicyDocument={"Statement": [{
                    "Action": [
                        "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                        "elasticloadbalancing:RegisterInstancesWithLoadBalancer"
                    ],
                    "Resource": [
                        Join("", [
                            "arn:aws:elasticloadbalancing:",
                            Ref("AWS::Region"),
                            ":",
                            Ref("AWS::AccountId"),
                            ':loadbalancer/',
                            Ref(load_balancer)
                        ])
                    ],
                    "Effect": "Allow"}
                ]},
                Roles=[Ref("BaseHostRole")],
            )
            elb_list.append(elb_role_policies)

            if "security_groups" in elb:
                load_balancer.SecurityGroups = []
                for sg_name, sg_rules in elb['security_groups'].items():
                    sg = SecurityGroup(
                        sg_name,
                        GroupDescription=sg_name,
                        SecurityGroupIngress=sg_rules,
                        VpcId=Ref("VPC")
                    )
                    load_balancer.SecurityGroups.append(Ref(sg))
                    elb_sgs.append(sg)
            else:
                sg = SecurityGroup(
                    "DefaultSG" + safe_name,
                    GroupDescription="DefaultELBSecurityGroup",
                    SecurityGroupIngress=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "CidrIp": "0.0.0.0/0"
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    VpcId=Ref("VPC")
                )
                load_balancer.SecurityGroups = [Ref(sg)]
                elb_sgs.append(sg)

            # Add outputs
            output_name = "ELB" + safe_name
            logging.debug("config:elb:Adding output to ELB '%s'" % (output_name))
            template.add_output(Output(
                output_name,
                Description="ELB DNSName",
                Value=GetAtt(load_balancer, "DNSName")
            ))

        # Update template with ELB resources
        map(template.add_resource, elb_list)
        map(template.add_resource, elb_sgs)
        template = self._attach_elbs(template)

    def _convert_ref_dict_to_objects(self, o):
        """
        Some troposphere objects need troposphere.Ref objects instead of a
        plain dict of {"Ref": "x" }. This helper function will do such
        transformations and return a new dict
        """
        def ref_fixup(x):
            if isinstance(x, dict) and "Ref" in x:
                return Ref(x["Ref"])
            else:
                return x
        return dict([(k, ref_fixup(v)) for k, v in o.items()])

    def get_ec2_userdata(self):
        """
        Build and return the user_data that'll be used for ec2 instances.
        This contains a series of required entries, default config, and
        and data specified in the template.
        """
        os_data = self._get_os_data()
        data = self.data['ec2']
        parts = []

        ami_type = os_data.get('type')

        # Below is the ami flavour specific defaults
        if ami_type == 'linux':
            parts.append({
                'content': yaml.dump(
                    {
                        'package_update': True,
                        'package_upgrade': True,
                        'package_reboot_if_required': True
                    }
                ),
                'mime_type': 'text/cloud-config'
            })

        boothook = self.get_hostname_boothook(data)

        if boothook:
            parts.append(boothook)

        if "cloud_config" in data:
            parts.append({
                'content': yaml.dump(data['cloud_config']),
                'mime_type': 'text/cloud-config'
            })
        elif boothook:
            # If the hostname boothook is specified then make sure we include
            # the 'manage_hostname' cloud-init config so that `sudo` doesn't
            # complaint about unable to resolve host name
            parts.append({
                'content': yaml.dump({'manage_etc_hosts': True}),
                'mime_type': 'text/cloud-config'
            })

        if len(parts):
            return parts

    HOSTNAME_BOOTHOOK_TEMPLATE = textwrap.dedent("""\
    #!/bin/sh
    [ -e /etc/cloud/cloud.cfg.d/99_hostname.cfg ] || echo "hostname: {hostname}" > /etc/cloud/cloud.cfg.d/99_hostname.cfg
    """)

    DEFAULT_HOSTNAME_PATTERN = "{instance_id}.{environment}.{application}"

    def get_hostname_boothook(self, data):
        """
        Return a boothook part that will set the hostname of instances on boot.

        The pattern comes from the ``hostname_pattern`` pattern of data dict,
        with a default of "{instance_id}.{environment}.{application}". To
        disable this functionality explicitly pass None in this field.
        """
        hostname_pattern = data.get('hostname_pattern', self.DEFAULT_HOSTNAME_PATTERN)
        if hostname_pattern is None:
            return None

        interploations = {
            # This gets interploated by cloud-init at run time.
            'instance_id': '${INSTANCE_ID}',
            'tags': data['tags'],
            'environment': self.environment,
            'application': self.application,
            'stack_name': self.stack_name,
        }
        try:
            hostname = hostname_pattern.format(**interploations)
        except KeyError as e:
            raise errors.CfnHostnamePatternError("Error interpolating hostname_pattern '{pattern}' - {key} is not a valid interpolation".format(
                pattern=hostname_pattern,
                key=e.args[0]))

        # Warn the user that they probably want to set 'manage_etc_hosts'
        if "cloud_config" in data and "manage_etc_hosts" not in data['cloud_config']:
            logging.warning(
                "config: 'hostname_pattern' boothook is being " +
                "generated but 'manage_etc_hosts' has not been specified in " +
                "'cloud_config' -- you probably want to specify this as True " +
                "otherwise you will get hostname resolution errors."
            )

        return {
            'mime_type': 'text/cloud-boothook',
            'content': self.HOSTNAME_BOOTHOOK_TEMPLATE.format(hostname=hostname)
        }

    def ec2(self):
        # LOAD STACK TEMPLATE
        data = self.data['ec2']
        resources = []
        sgs = []

        for sg_name, ingress in data['security_groups'].items():
            sg = SecurityGroup(
                sg_name,
                VpcId=Ref("VPC"),
                GroupDescription="BaseHost Security Group",
            )

            sgs.append(sg)
            resources.append(sg)

            # Because we want to be able to add ingress rules to a security
            # group that referes to itself (for example allow all instances in
            # the sg to speak to each other on 9300 for Elasticsearch
            # clustering) we create the SG in one resource and rules as other
            # resources
            #
            # The yaml for this case is:
            #
            # security_groups:
            #   EScluster:
            #     - FromPort: 9300
            #     - ToPort: 9300
            #     - SourceSecurityGroupId: { Ref: EScluster }
            for idx, rule in enumerate(ingress):
                # Convert { Ref: "x"} to Ref("x")
                rule = self._convert_ref_dict_to_objects(rule)

                ingress = SecurityGroupIngress(
                    "{}Rule{}".format(sg_name, idx),
                    GroupId=Ref(sg),
                    **rule)
                resources.append(ingress)

        devices = []
        try:
            for i in data['block_devices']:
                device_name = i['DeviceName']
                volume_size = i.get('VolumeSize', 20)
                volume_type = i.get('VolumeType', 'standard')
                iops = i.get('Iops', None)
                # Check we have a permitted volume type
                if volume_type not in ['standard', 'gp2', 'io1']:
                    raise errors.CfnConfigError("config: Volume type '%s' but must be one of standard', 'gp2' or 'io1"
                                                % (volume_type))
                # We need to specifiy iops if we have a volume type of io1
                if volume_type == 'io1' and not iops:
                    raise errors.CfnConfigError("config: Volume type io1 must have Iops defined")

                # We dont set a default for iops and troposphere doesnt handle this well
                if not iops:
                    ebs = EBSBlockDevice(VolumeType=volume_type, VolumeSize=volume_size)
                else:
                    ebs = EBSBlockDevice(VolumeType=volume_type, VolumeSize=volume_size, Iops=iops)

                devices.append(BlockDeviceMapping(
                    DeviceName=device_name,
                    Ebs=ebs
                ))

        except KeyError:
            devices.append(BlockDeviceMapping(
                DeviceName="/dev/sda1",
                Ebs=EBSBlockDevice(VolumeSize=20),
            ))

        launch_config = LaunchConfiguration(
            "BaseHostLaunchConfig",
            KeyName=data['parameters']['KeyName'],
            SecurityGroups=[Ref(g) for g in sgs],
            InstanceType=data['parameters']['InstanceType'],
            AssociatePublicIpAddress=True,
            IamInstanceProfile=Ref("InstanceProfile"),
            ImageId=FindInMap("AWSRegion2AMI", Ref("AWS::Region"), "AMI"),
            BlockDeviceMappings=devices,
        )

        user_data = self.get_ec2_userdata()
        if user_data:
            user_data = mime_packer.pack(user_data)
            launch_config.UserData = Base64(user_data)

        resources.append(launch_config)

        # Allow deprecation of tags
        ec2_tags = []
        deprecated_tags = ["Env"]
        # Add a name tag for easy ec2 instance identification in the AWS console
        if data['tags'].get("Name", None) is None:
            ec2_tags.append(self._get_default_resource_name_tag(type="ec2"))
        # Get all tags from the config
        for k, v in data['tags'].items():
            if k not in deprecated_tags:
                ec2_tags.append(Tag(k, v, True))
            else:
                logging.warning("config: Tag '%s' is deprecated.."
                                % (k))

        # Setup ASG defaults
        auto_scaling_config = data.get('auto_scaling', {})
        asg_min_size = auto_scaling_config.get('min', 1)
        asg_max_size = auto_scaling_config.get('max', 5)
        asg_desired_size = auto_scaling_config.get('desired', 2)
        health_check_type = auto_scaling_config.get('health_check_type', 'EC2').upper()
        # The basic EC2 healthcheck has a low grace period need, if we switch to ELB then
        # theres a lot more setup to be done before we should attempt a healthcheck
        if health_check_type == 'ELB':
            default_health_check_grace_period = 600
        else:
            default_health_check_grace_period = 300
        health_check_grace_period = auto_scaling_config.get('health_check_grace_period', default_health_check_grace_period)
        scaling_group = AutoScalingGroup(
            "ScalingGroup",
            VPCZoneIdentifier=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")],
            MinSize=asg_min_size,
            MaxSize=asg_max_size,
            DesiredCapacity=asg_desired_size,
            AvailabilityZones=GetAZs(),
            Tags=ec2_tags,
            LaunchConfigurationName=Ref(launch_config),
            HealthCheckGracePeriod=health_check_grace_period,
            HealthCheckType=health_check_type,
        )
        resources.append(scaling_group)

        return resources

    @classmethod
    def _find_resources(cls, template, resource_type):
        f = lambda x: x.resource_type == resource_type
        return filter(f, template.resources.values())

    @classmethod
    def _get_elb_canonical_name(cls, elb_yaml_name):
        return 'ELB-{}'.format(elb_yaml_name.replace('.', ''))

    def _attach_elbs(self, template):
        if 'elb' not in self.data:
            return template
        asgs = self._find_resources(template,
                                    'AWS::AutoScaling::AutoScalingGroup')
        if len(asgs) > 0:
            elbs = self._find_resources(template,
                                        'AWS::ElasticLoadBalancing::LoadBalancer')
            asgs[0].LoadBalancerNames = [Ref(x) for x in elbs]
            template.resources[asgs[0].title] = asgs[0]

        return template

    def _get_os_data(self):
        """
        Get details about the OS from the config data

        Return:
            os_data(dict): Dictionary of OS data in the form
                {
                    'name': 'ubuntu-1404',
                    'ami': 'ami-f9a62c8a',
                    'region': 'eu-west-1',
                    'distribution': 'ubuntu',
                    'type': 'linux',
                    'release': '20160509.1'
                }

        Exceptions:
            OSTypeNotFoundError: Raised when the OS in the config file is not
                recognised
        """
        os_default = 'ubuntu-1404'
        available_types = {
            'ubuntu-1404': {
                'name': 'ubuntu-1404',
                'ami': 'ami-f95ef58a',
                'region': 'eu-west-1',
                'distribution': 'ubuntu',
                'type': 'linux',
                'release': '20160509.1'
            },
            'windows2012': {
                'name': 'windows2012',
                'ami': 'ami-8519a9f6',
                'region': 'eu-west-1',
                'distribution': 'windows',
                'type': 'windows',
                'release': '2015.12.31'
            }
        }
        os_choice = self.data['ec2'].get('os', os_default)
        if not available_types.get(os_choice, False):
            raise errors.OSTypeNotFoundError(self.data['ec2']['os'], available_types.keys())
        os_data = available_types.get(os_choice)
        ami = self.data['ec2'].get('ami')
        if ami:
            logging.info('** Using override AMI of ' + str(ami))
            os_data['ami'] = ami
            logging.info('overridden os data is: ' + repr(os_data))
        return os_data

    def _get_default_resource_name_tag(self, type):
        """
        Get the name tag we will use for ec2 instances

        Returns:
            name_tag(string): The Name: tag to use.
            type(string): The type of the resource
        """
        # Use the stack name as the tag
        value = Join("", [{"Ref": "AWS::StackName"}, "-", type])
        name_tag = Tag("Name", value, True)
        return name_tag
