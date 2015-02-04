import sys
import boto.ec2

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

    def get_instance_public_ips(self, instance_id_list):
        if not instance_id_list:
            return []
        return [x.ip_address for x in 
                self.conn_ec2.get_only_instances(instance_ids=instance_id_list)]
