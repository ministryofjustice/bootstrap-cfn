import sys
import boto.ec2
from bootstrap_cfn import cloudformation
from bootstrap_cfn import ssh
from bootstrap_cfn import utils

class EC2:

    conn_cfn = None
    config = None

    def __init__(self, config):
        self.config = config
        if self.config.aws_access is not None and self.config.aws_secret is not None:
            self.conn_ec2 = boto.ec2.connect_to_region(
                region_name=self.config.aws_region,
                aws_access_key_id=self.config.aws_access,
                aws_secret_access_key=self.config.aws_secret)
        else:
            print "[ERROR] No AWS credentials"
            sys.exit(1)
        self.cfn = cloudformation.Cloudformation(config)

    def get_instance_public_ips(self, instance_id_list):
        if not instance_id_list:
            return []
        return [x.ip_address for x in
                self.conn_ec2.get_only_instances(instance_ids=instance_id_list)]

    def get_instance_private_ips(self, instance_id_list):
        if not instance_id_list:
            return []
        return [x.private_ip_address for x in
                self.conn_ec2.get_only_instances(instance_ids=instance_id_list)]

    def set_instance_tags(self, instance_ids, tags={}):
        return self.conn_ec2.create_tags(instance_ids, tags)

    def create_sg(self, name):
        return self.conn_ec2.create_security_group(
            name, 'bootstrap generated SG')

    def get_sg(self, name):
        groups = self.conn_ec2.get_all_security_groups(groupnames=[name])
        return groups[0] if groups else None

    def add_minion_to_sg(self, sg_obj, ip):
        return sg_obj.authorize(
            ip_protocol='tcp', from_port=4505, to_port=4506, cidr_ip='{0}/32'.format(ip))

    def get_instance_by_id(self, inst_id):
        resv = self.conn_ec2.get_all_reservations([inst_id])
        return [i for r in resv for i in r.instances][0] if resv else None

    def get_master_instance(self, stack_name_or_id, master_tag_name='SaltMaster'):
        stack_instances = self.cfn.get_stack_instances(stack_name_or_id)
        stack_instance_ids = [x.instance_id for x in stack_instances]
        filters = {'tag-key': master_tag_name,
                   'instance-state-name': 'running',
                   'instance-id': stack_instance_ids}
        resv = self.conn_ec2.get_all_reservations(filters=filters)
        return [i for r in resv for i in r.instances][0] if resv else None

    def get_minions(self, stack_name_or_id,
                    minion_tag_name='SaltMasterPrvIP', remove_master=False):
        resv = self.conn_ec2.get_all_reservations(
            filters={ 'tag-key': minion_tag_name,
                      'instance-id': self.cfn.get_stack_instances(stack_name_or_id)
                    })
        instances = [i for r in resv for i in r.instances]
        if remove_master:
            instances.remove(self.get_master_instance(stack_name_or_id))
        return instances

    def is_ssh_up_on_all_instances(self, stack_id):
        instances = self.get_instance_public_ips(self.cfn.get_stack_instance_ids(stack_id))
        if all([ssh.is_ssh_up(i) for i in instances]):
            return True
        return False

    def wait_for_ssh(self, stack_id, timeout=300, interval=30):
        return utils.timeout(timeout, interval)(self.is_ssh_up_on_all_instances)(stack_id)
