import sys
import boto.cloudformation


class Cloudformation:

    conn_cfn = None
    config = None

    def __init__(self, config):
        self.config = config
        if self.config.aws_access is not None and self.config.aws_secret is not None:
            self.conn_cfn = boto.cloudformation.connect_to_region(
                region_name=self.config.aws_region,
                aws_access_key_id=self.config.aws_access,
                aws_secret_access_key=self.config.aws_secret)
        else:
            print "[ERROR] No AWS credentials"
            sys.exit(1)

    def create(self, stack_name, template_body):
        stack = self.conn_cfn.create_stack(stack_name=stack_name,
                                          template_body=template_body,
                                          capabilities=['CAPABILITY_IAM'])

        print "\n\n\n%s\n\n\nSTACK CREATED" % stack
