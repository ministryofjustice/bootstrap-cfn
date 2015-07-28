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

    def __init__(self, config, environment, passwords=None):
        try:
            self.config = self.load_yaml(config)[environment]
        except KeyError:
            raise errors.BootstrapCfnError("Environment " + environment + " not found")

        if passwords:
            passwords_dict = self.load_yaml(passwords)[environment]
            self.config = utils.dict_merge(self.config, passwords_dict)

    @staticmethod
    def load_yaml(fp):
        if os.path.exists(fp):
            return yaml.load(open(fp).read())


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
            elbs, sgs = self.elb()
            map(template.add_resource, elbs)
            map(template.add_resource, sgs)
            template = self._attach_elbs(template)

        if 'rds' in self.data:
            self.rds(template)

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

        t = Template()

        t.add_mapping("AWSRegion2AMI", {
            "eu-west-1": {"AMI": "ami-f0b11187"},
        })

        if 'vpc' in self.data:
            t.add_mapping("SubnetConfig", {
                "VPC": self.data['vpc']
            })
        else:
            t.add_mapping("SubnetConfig", {
                "VPC": {
                    "CIDR": "10.0.0.0/16",
                    "SubnetA": "10.0.0.0/20",
                    "SubnetB": "10.0.16.0/20",
                    "SubnetC": "10.0.32.0/20"
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

        role_policies = PolicyType(
            "RolePolicies",
            PolicyName="BaseHost",
            PolicyDocument={"Statement": [
                {"Action": ["autoscaling:Describe*"], "Resource": "*", "Effect": "Allow"},
                {"Action": ["ec2:Describe*"], "Resource": "*", "Effect": "Allow"},
                {"Action": ["rds:Describe*"], "Resource": "*", "Effect": "Allow"},
                {"Action": ["elasticloadbalancing:Describe*"], "Resource": "*", "Effect": "Allow"},
                {"Action": ["elasticache:Describe*"], "Resource": "*", "Effect": "Allow"},
                {"Action": ["cloudformation:Describe*"], "Resource": "*", "Effect": "Allow"},
                {"Action": ["s3:List*"], "Resource": "*", "Effect": "Allow"}
            ]},
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
                The cloudformation template file
        """
        # As there are no required fields, although we may not have any
        # subkeys we still need to be able to have a parent key 's3:' to
        # signify that we want to create an s3 bucket. In this case we
        # set up an empty (no options set) dictionary
        present_keys = {}
        if isinstance(self.data['s3'], dict):
            present_keys = self.data['s3'].keys()

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

    def ssl(self):
        return self.data['ssl']

    def rds(self, template):
        """
        Create an RDS resource configuration from the config file data
        and add it to the troposphere template. Outputs for the RDS name,
        host and port are created.

        Args:
            template:
                The cloudformation template file
        """
        # REQUIRED FIELDS MAPPING
        required_fields = {
            'db-name': 'DBName',
            'storage': 'AllocatedStorage',
            'storage-type': 'StorageType',
            'backup-retention-period': 'BackupRetentionPeriod',
            'db-master-username': 'MasterUsername',
            'db-master-password': 'MasterUserPassword',
            'db-engine': 'Engine',
            'db-engine-version': 'EngineVersion',
            'instance-class': 'DBInstanceClass',
            'multi-az': 'MultiAZ'
        }

        optional_fields = {
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
            StorageEncrypted=False,
            DependsOn=database_sg.title
        )
        resources.append(rds_instance)

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

    def elb(self):
        # REQUIRED FIELDS AND MAPPING
        required_fields = {
            'listeners': 'Listeners',
            'scheme': 'Scheme',
            'name': 'LoadBalancerName',
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

            load_balancer = LoadBalancer(
                "ELB" + safe_name,
                Subnets=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")],
                Listeners=elb['listeners'],
                Scheme=elb['scheme'],
                LoadBalancerName=self._get_elb_canonical_name(elb['name']),
                ConnectionDrainingPolicy=ConnectionDrainingPolicy(
                    Enabled=True,
                    Timeout=120,
                ),
                Policies=[
                    Policy(
                        Attributes=[{'Name': "Reference-Security-Policy", 'Value': "ELBSecurityPolicy-2015-05"}],
                        PolicyType='SSLNegotiationPolicyType',
                        PolicyName='PinDownSSLNegotiationPolicy201505'
                    )
                ]
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
                            ':loadbalancer/%s' % load_balancer.LoadBalancerName
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
        return elb_list, elb_sgs

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
        data = self.data['ec2']

        parts = []

        boothook = self.get_hostname_boothook(data)

        if boothook:
            parts.append(boothook)

        if "cloud_config" in data:
            parts.append({
                'content': yaml.dump(data['cloud_config']),
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
                devices.append(BlockDeviceMapping(
                    DeviceName=i['DeviceName'],
                    Ebs=EBSBlockDevice(VolumeSize=i['VolumeSize']),
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
        for k, v in data['tags'].items():
            if k not in deprecated_tags:
                ec2_tags.append(Tag(k, v, True))
            else:
                logging.warning("config: Tag '%s' is deprecated.."
                                % (k))

        scaling_group = AutoScalingGroup(
            "ScalingGroup",
            VPCZoneIdentifier=[Ref("SubnetA"), Ref("SubnetB"), Ref("SubnetC")],
            MinSize=data['auto_scaling']['min'],
            MaxSize=data['auto_scaling']['max'],
            DesiredCapacity=data['auto_scaling']['desired'],
            AvailabilityZones=GetAZs(),
            Tags=ec2_tags,
            LaunchConfigurationName=Ref(launch_config),
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
        elbs = self._find_resources(template,
                                    'AWS::ElasticLoadBalancing::LoadBalancer')

        asgs[0].LoadBalancerNames = [x.LoadBalancerName for x in elbs]
        template.resources[asgs[0].title] = asgs[0]

        return template
