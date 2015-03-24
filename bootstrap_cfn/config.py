import json
import os
import pkgutil
import sys
import yaml
import bootstrap_cfn.errors as errors
from copy import deepcopy


class AWSConfig:

    aws_access = None
    aws_secret = None
    aws_region = 'eu-west-1'

    def __init__(self, account, fp=None):
        if fp:
            if os.path.exists(fp):
                f = open(fp).read()
            else:
                raise IOError
        else:
            f = open(os.path.expanduser("~") + "/.config.yaml").read()

        try:
            if f:
                d = yaml.load(f)['provider_zones']
                self.aws_access = d[account]['aws_access_key_id']
                self.aws_secret = d[account]['aws_secret_access_key']
        except KeyError:
            raise


class ProjectConfig:

    config = None

    def __init__(self, config, environment, passwords=None):
        self.config = self.load_yaml(config)[environment]
        if passwords:
            passwords_dict = self.load_yaml(passwords)[environment]
            self.config = self.dict_merge(self.config, passwords_dict)

    @staticmethod
    def load_yaml(fp):
        if os.path.exists(fp):
            return yaml.load(open(fp).read())

    def dict_merge(self, target, *args):
        # Merge multiple dicts
        if len(args) > 1:
            for obj in args:
                self.dict_merge(target, obj)
            return target

        # Recursively merge dicts and set non-dict values
        obj = args[0]
        if not isinstance(obj, dict):
            return obj
        for k, v in obj.iteritems():
            if k in target and isinstance(target[k], dict):
                self.dict_merge(target[k], v)
            else:
                target[k] = deepcopy(v)
        return target


class ConfigParser:

    config = {}

    def __init__(self, data, stack_name):
        self.stack_name = stack_name
        self.data = data

    def process(self):
        vpc = self.vpc()
        iam = self.iam()
        ec2 = self.ec2()
        rds = {}
        s3 = {}
        elb = {}
        output_templates = []

        if 'rds' in self.data:
            rds = self.rds()
            output_templates.append('stacks/rds_out.json')
        if 's3' in self.data:
            s3 = self.s3()
        if 'elb' in self.data:
            elb, elb_sgs = self.elb()
            # GET LIST OF ELB NAMES AND ADD TO EC2 INSTANCES
            elb_name_list = []
            for i in elb:
                if i.keys()[0][0:3] == "ELB":
                    elb_name_list.append(
                        i[i.keys()[0]]['Properties']['LoadBalancerName'])
            ec2['ScalingGroup']['Properties'][
                'LoadBalancerNames'] = elb_name_list

        # LOAD BASE TEMPLATE AND INSERT AWS SERVICES
        data = iam
        data.update(vpc)
        data.update(ec2)
        data.update(rds)
        data.update(s3)
        for i in elb:
            data.update(i)
        for k,v in elb_sgs.items():
            data[k] = v

        template = json.loads(pkgutil.get_data('bootstrap_cfn', 'stacks/base.json'))
        template['Resources'] = data
        template['Outputs'] = {}
        for t in output_templates:
            template['Outputs'].update(json.loads(pkgutil.get_data('bootstrap_cfn', t)))
        return json.dumps(
            template, sort_keys=True, indent=4, separators=(',', ': '))

    def vpc(self):
        # LOAD STACK TEMPLATE
        return json.loads(pkgutil.get_data('bootstrap_cfn', 'stacks/vpc.json'))

    def iam(self):
        # LOAD STACK TEMPLATE
        return json.loads(pkgutil.get_data('bootstrap_cfn', 'stacks/iam.json'))

    def s3(self):
        # REQUIRED FIELDS AND MAPPING
        required_fields = {
            'static-bucket-name': 'BucketName'
        }

        # LOAD STACK TEMPLATE
        template = json.loads(pkgutil.get_data('bootstrap_cfn', 'stacks/s3.json'))

        # TEST FOR REQUIRED FIELDS AND EXIT IF MISSING ANY
        present_keys = self.data['s3'].keys()
        for i in required_fields.keys():
            if i not in present_keys:
                print "\n\n[ERROR] Missing S3 fields [%s]" % i
                sys.exit(1)

        #policy = None
        if 'policy' in present_keys:
            policy = json.loads(open(self.data['policy']).read())
        else:
             arn = 'arn:aws:s3:::%s/*' % self.data['s3']['static-bucket-name']
             policy = {'Action': ['s3:Get*', 's3:Put*', 's3:List*'], 'Resource': arn, 'Effect': 'Allow', 'Principal' : {'AWS' : '*'}}

        template['StaticBucket']['Properties']['BucketName'] = self.data['s3']['static-bucket-name']
        template['StaticBucketPolicy']['Properties']['PolicyDocument']['Statement'][0] = policy

        return template

    def ssl(self):
        return self.data['ssl']

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
        template = json.loads(pkgutil.get_data('bootstrap_cfn', 'stacks/rds.json'))

        # TEST FOR REQUIRED FIELDS AND EXIT IF MISSING ANY
        for i in required_fields.keys():
            if i not in self.data['rds'].keys():
                print "\n\n[ERROR] Missing RDS fields [%s]" % i
                sys.exit(1)
            else:
                template['RDSInstance']['Properties'][
                    required_fields[i]] = self.data['rds'][i]

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
        elb_sgs = {}
        # COULD HAVE MULTIPLE ELB'S (PUBLIC / PRIVATE etc)
        for elb in self.data['elb']:
            safe_name = elb['name'].replace('-', '').replace('.', '')
            # TEST FOR REQUIRED FIELDS AND EXIT IF MISSING ANY
            for i in required_fields.keys():
                if i not in elb.keys():
                    print "\n\n[ERROR] Missing ELB fields [%s]" % i
                    sys.exit(1)

            # LOAD STACK TEMPLATE
            template = json.loads(pkgutil.get_data('bootstrap_cfn', 'stacks/elb.json'))

            # LOAD SSL TEMPLATE
            ssl_template = json.loads(pkgutil.get_data('bootstrap_cfn', 'stacks/elb_ssl.json'))

            for listener in elb['listeners']:
                if listener['Protocol'] == 'HTTPS':
                    try:
                        cert_name = elb['certificate_name']
                    except KeyError:
                        raise errors.CfnConfigError("HTTPS listener but no certificate_name specified")
                    try:
                        self.ssl()[cert_name]['cert']
                        self.ssl()[cert_name]['key']
                    except KeyError:
                        raise errors.CfnConfigError("Couldn't find ssl cert {0} in config file".format(cert_name))
                    ssl_template["SSLCertificateId"]['Fn::Join'][1].append("{0}-{1}".format(cert_name, self.stack_name))
                    listener.update(ssl_template)


            elb_sg = template.pop('DefaultELBSecurityGroup')
            if 'security_groups' in elb:
                for sg_name, sg in elb['security_groups'].items():
                    new_sg = deepcopy(elb_sg)
                    new_sg['Properties']['SecurityGroupIngress'] = sg
                    elb_sgs[sg_name + safe_name] = new_sg
                template['ElasticLoadBalancer']['Properties']['SecurityGroups'] = [{'Ref': k + safe_name} for k in elb['security_groups'].keys()]
            else:
                elb_sgs['DefaultSG' + safe_name] = elb_sg
                template['ElasticLoadBalancer']['Properties']['SecurityGroups'] = [{'Ref': 'DefaultSG' + safe_name }]

            # CONFIGURE THE LISTENERS, ELB NAME AND ROUTE53 RECORDS
            template['ElasticLoadBalancer']['Properties'][
                'Listeners'] = elb['listeners']
            template['ElasticLoadBalancer']['Properties'][
                'LoadBalancerName'] = 'ELB-%s' % elb['name'].replace('.', '')
            template['ElasticLoadBalancer'][
                'Properties']['Scheme'] = elb['scheme']
            template['DNSRecord']['Properties'][
                'HostedZoneName'] = elb['hosted_zone']
            template['DNSRecord']['Properties']['RecordSets'][0][
                'Name'] = "%s.%s" % (elb['name'], elb['hosted_zone'])
            target_zone = [
                'ELB%s' % safe_name,
                'CanonicalHostedZoneNameID']
            target_dns = [
                'ELB%s' % safe_name,
                'CanonicalHostedZoneName']
            template['DNSRecord']['Properties']['RecordSets'][0][
                'AliasTarget']['HostedZoneId']['Fn::GetAtt'] = target_zone
            template['DNSRecord']['Properties']['RecordSets'][0][
                'AliasTarget']['DNSName']['Fn::GetAtt'] = target_dns

            elb_list.append(
                {'ELB%s' % safe_name: template['ElasticLoadBalancer']})
            elb_list.append(
                {'DNS%s' % safe_name: template['DNSRecord']})

        return elb_list, elb_sgs

    def ec2(self):
        # LOAD STACK TEMPLATE
        template = json.loads(pkgutil.get_data('bootstrap_cfn', 'stacks/ec2.json'))

        # SET SECURITY GROUPS, DEFAULT KEY AND INSTANCE TYPE
        sg_t = template.pop('BaseHostSG')
        for sg_name, sg in self.data['ec2']['security_groups'].items():
            new_sg = deepcopy(sg_t)
            new_sg['Properties']['SecurityGroupIngress'] = sg
            template[sg_name] = new_sg

        template['BaseHostLaunchConfig']['Properties']['SecurityGroups'] = [{'Ref': k} for k in self.data['ec2']['security_groups'].keys()]
        template['BaseHostLaunchConfig']['Properties'][
            'KeyName'] = self.data['ec2']['parameters']['KeyName']
        template['BaseHostLaunchConfig']['Properties'][
            'InstanceType'] = self.data['ec2']['parameters']['InstanceType']

        # BLOCK DEVICE MAPPING
        devices = []
        for i in self.data['ec2']['block_devices']:
            devices.append(
                {'DeviceName': i['DeviceName'], 'Ebs': {'VolumeSize': i['VolumeSize']}})
        template['BaseHostLaunchConfig']['Properties'][
            'BlockDeviceMappings'] = devices

        # SET AUTO SCALING PARAMETERS
        template['ScalingGroup']['Properties'][
            'MinSize'] = self.data['ec2']['auto_scaling']['min']
        template['ScalingGroup']['Properties'][
            'MaxSize'] = self.data['ec2']['auto_scaling']['max']
        template['ScalingGroup']['Properties'][
            'DesiredCapacity'] = self.data['ec2']['auto_scaling']['desired']

        # SET INSTANCE TAGS
        tags = []
        for i in self.data['ec2']['tags']:
            tags.append({'Key': i,
                         'Value': self.data['ec2']['tags'][i],
                         'PropagateAtLaunch': True})
        template['ScalingGroup']['Properties']['Tags'] = tags

        return template
