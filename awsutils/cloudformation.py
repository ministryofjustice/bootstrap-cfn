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

    def modify_sg(self, stack_data, sg_data):
        groups = []
        for sg in sg_data:
            sg_struct = {
                    'Type': 'AWS::EC2::SecurityGroup',
                    'Properties': {
                        'GroupDescription': 'Auto generated SG',
                        'SecurityGroupIngress': sg_data[sg]['rules']
                    }
                }
            stack_data['Resources'][sg] = sg_struct
        return stack_data

    def create(self, stack_name, template_body):
        return self.conn_cfn.create_stack(stack_name=stack_name, template_body=template_body)

    def stack_done(self, stack_id):
        stack_events = self.conn_cfn.describe_stack_events(stack_id)
        if stack_events[0].resource_type == 'AWS::CloudFormation::Stack'\
                and stack_events[0].resource_status in ['CREATE_COMPLETE', 'CREATE_FAILED']:
            return True
        return False

    def get_last_stack_event(self, stack_id):
        return self.conn_cfn.describe_stack_events(stack_id)[0]

