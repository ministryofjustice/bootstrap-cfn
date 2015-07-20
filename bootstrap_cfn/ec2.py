import boto.ec2

from bootstrap_cfn import cloudformation
from bootstrap_cfn import utils


class EC2:

    conn_cfn = None
    aws_region_name = None
    aws_profile_name = None

    def __init__(self, aws_profile_name, aws_region_name='eu-west-1'):
        self.aws_profile_name = aws_profile_name
        self.aws_region_name = aws_region_name

        self.conn_ec2 = utils.connect_to_aws(boto.ec2, self)

        self.cfn = cloudformation.Cloudformation(
            aws_profile_name=aws_profile_name,
            aws_region_name=aws_region_name
        )

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
