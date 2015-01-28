import sys
import os
import yaml
import json
import random


class AWSConfig:

    aws_access = None
    aws_secret = None
    aws_region = 'eu-west-1'

    def __init__(self, account, fp=False):
        f = None
        if fp is True:
            if os.path.exists(fp):
                f = open(fp).read()
            else:
                print "File does not exist"
                sys.exit(1)
        else:
            f = open(os.path.expanduser("~") + "/.config.yaml").read()

        if f:
            d = yaml.load(f)['provider_zones']
            self.aws_access = d[account]['aws_access_key_id']
            self.aws_secret = d[account]['aws_secret_access_key']


class ProjectConfig:

    config = None

    def __init__(self, config, environment):
        if os.path.exists(config):
            f = yaml.load(open(config).read())
            self.config = f[environment]


class ConfigParser:

    config = {}

    def __init__(self, data):
        self.data = data

    def process(self):
        iam = self.iam()
        ec2 = self.ec2()
        rds = {}
        s3 = {}
        elb = {}

        if 'rds' in self.data:
            rds = self.rds()
        if 's3' in self.data:
            s3 = self.s3()
            # ADD ADDITIONAL IAM ROLE DUE TO ADDING S3 BUCKET
            arn = s3['StaticBucketPolicy']['Properties']['PolicyDocument']['Statement'][0]['Resource']
            policy = {'Action': ['s3:Get*', 's3:Put*', 's3:List*'], 'Resource': arn, 'Effect': 'Allow'}
            iam['RolePolicies']['Properties']['PolicyDocument']['Statement'].append(policy)
        if 'elb' in self.data:
            elb = self.elb()

            # GET LIST OF ELB NAMES AND ADD TO EC2 INSTANCES
            elb_name_list = []
            for i in elb:
                if i.keys()[0][0:3] == "ELB":
                    elb_name_list.append(i[i.keys()[0]]['Properties']['LoadBalancerName'])
            ec2['ScalingGroup']['Properties']['LoadBalancerNames'] = elb_name_list



        # LOAD BASE TEMPLATE AND INSERT AWS SERVICES
        data = iam
        data.update(ec2)
        data.update(rds)
        data.update(s3)
        for i in elb:
            data.update(i)

        template = json.loads(open("%s/stacks/base.json" % os.getcwd()).read())
        template['Resources'] = data
        return json.dumps(template, sort_keys=True, indent=4, separators=(',', ': '))

    def iam(self):
        # LOAD STACK TEMPLATE
        return json.loads(open("%s/stacks/iam.json" % os.getcwd()).read())

    def s3(self):
        # REQUIRED FIELDS AND MAPPING
        required_fields = {
            'static-bucket-name': 'BucketName'
        }

        # LOAD STACK TEMPLATE
        template = json.loads(open("%s/stacks/s3.json" % os.getcwd()).read())

        # TEST FOR REQUIRED FIELDS AND EXIT IF MISSING ANY
        for i in required_fields.keys():
            if i not in self.data['s3'].keys():
                print "\n\n[ERROR] Missing S3 fields [%s]" % i
                sys.exit(1)

        # SET BUCKET NAME AND ARN
        arn = 'arn:aws:s3:::%s/*' % self.data['s3']['static-bucket-name']
        template['StaticBucketPolicy']['Properties']['PolicyDocument']['Statement'][0]['Resource'] = arn
        template['StaticBucket']['Properties']['BucketName'] = self.data['s3']['static-bucket-name']
        return template

    def rds(self):
        # REQUIRED FIELDS MAPPING
        required_fields = {
            'db-name': 'DBName',
            'storage': 'AllocatedStorage',
            'storage-type': 'StorageType',
            'backup-retention-period': 'BackupRetentionPeriod',
            'db-master-username': 'MasterUsername',
            'db-master-password': 'MasterUserPassword',
            'identifier': 'DBInstanceIdentifier',
            'db-engine': 'Engine',
            'db-engine-version': 'EngineVersion',
            'instance-class': 'DBInstanceClass',
            'multi-az': 'MultiAZ'
        }

        # LOAD STACK TEMPLATE
        template = json.loads(open("%s/stacks/rds.json" % os.getcwd()).read())

        # TEST FOR REQUIRED FIELDS AND EXIT IF MISSING ANY
        for i in required_fields.keys():
            if i not in self.data['rds'].keys():
                print "\n\n[ERROR] Missing RDS fields [%s]" % i
                sys.exit(1)
            else:
                template['RDSInstance']['Properties'][required_fields[i]] = self.data['rds'][i]

        return template

    def elb(self):
        # REQUIRED FIELDS AND MAPPING
        required_fields = {
            'listeners': 'Listeners',
            'scheme': 'Scheme',
            'name': 'LoadBalancerName',
            'hosted_zone': 'HostedZoneName'
        }

        elb_list = []

        # COULD HAVE MULTIPLE ELB'S (PUBLIC / PRIVATE etc)
        for elb in self.data['elb']:
            # TEST FOR REQUIRED FIELDS AND EXIT IF MISSING ANY
            for i in required_fields.keys():
                if i not in elb.keys():
                    print "\n\n[ERROR] Missing ELB fields [%s]" % i
                    sys.exit(1)

            # LOAD STACK TEMPLATE
            template = json.loads(open("%s/stacks/elb.json" % os.getcwd()).read())

            # CONFIGURE THE LISTENERS, ELB NAME AND ROUTE53 RECORDS
            template['ElasticLoadBalancer']['Properties']['Listeners'] = elb['listeners']
            template['ElasticLoadBalancer']['Properties']['LoadBalancerName'] = 'ELB-%s' % elb['name']
            template['ElasticLoadBalancer']['Properties']['Scheme'] = elb['scheme']
            template['DNSRecord']['Properties']['HostedZoneName'] = elb['hosted_zone']
            template['DNSRecord']['Properties']['RecordSets'][0]['Name'] = "%s.%s" % (elb['name'], elb['hosted_zone'])
            target_zone = ['ELB%s' % elb['name'].replace('-', ''), 'CanonicalHostedZoneNameID']
            target_dns = ['ELB%s' % elb['name'].replace('-', ''), 'CanonicalHostedZoneName']
            template['DNSRecord']['Properties']['RecordSets'][0]['AliasTarget']['HostedZoneId']['Fn::GetAtt'] = target_zone
            template['DNSRecord']['Properties']['RecordSets'][0]['AliasTarget']['DNSName']['Fn::GetAtt'] = target_dns

            elb_list.append({'ELB%s' % elb['name'].replace('-', ''): template['ElasticLoadBalancer']})
            elb_list.append({'DNS%s' % elb['name'].replace('-', ''): template['DNSRecord']})

        return elb_list

    def ec2(self):
        # LOAD STACK TEMPLATE
        template = json.loads(open("%s/stacks/ec2.json" % os.getcwd()).read())

        # SET SECURITY GROUPS, DEFAULT KEY AND INSTANCE TYPE
        template['BaseHostSG']['Properties']['SecurityGroupIngress'] = self.data['ec2']['security_groups']
        template['BaseHostLaunchConfig']['Properties']['KeyName'] = self.data['ec2']['parameters']['KeyName']
        template['BaseHostLaunchConfig']['Properties']['InstanceType'] = self.data['ec2']['parameters']['InstanceType']

        # BLOCK DEVICE MAPPING
        devices = []
        for i in self.data['ec2']['block_devices']:
            devices.append({'DeviceName': i['DeviceName'], 'Ebs': {'VolumeSize': i['VolumeSize']}})
        template['BaseHostLaunchConfig']['Properties']['BlockDeviceMappings'] = devices

        # SET AUTO SCALING PARAMETERS
        template['ScalingGroup']['Properties']['MinSize'] = self.data['ec2']['auto_scaling']['min']
        template['ScalingGroup']['Properties']['MaxSize'] = self.data['ec2']['auto_scaling']['max']
        template['ScalingGroup']['Properties']['DesiredCapacity'] = self.data['ec2']['auto_scaling']['desired']

        # SET INSTANCE TAGS
        tags = []
        for i in self.data['ec2']['tags']:
            tags.append({'Key': i, 'Value': self.data['ec2']['tags'][i], 'PropagateAtLaunch': True})
        template['ScalingGroup']['Properties']['Tags'] = tags

        return template
