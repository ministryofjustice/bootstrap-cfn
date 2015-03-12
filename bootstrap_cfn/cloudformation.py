import sys
import boto.cloudformation
import boto.ec2
from boto.ec2 import autoscale
from bootstrap_cfn import utils


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
        return stack

    def delete(self, stack_name):
        stack = self.conn_cfn.delete_stack(stack_name)
        return stack

    def stack_done(self, stack_id):
        stack_events = self.conn_cfn.describe_stack_events(stack_id)
        if stack_events[0].resource_type == 'AWS::CloudFormation::Stack'\
                and stack_events[0].resource_status in ['CREATE_COMPLETE', 'CREATE_FAILED', 'ROLLBACK_COMPLETE']:
            return True
        return False

    def wait_for_stack_done(self, stack_id, timeout=3600, interval=30):
        return utils.timeout(timeout, interval)(self.stack_done)(stack_id)

    def get_last_stack_event(self, stack_id):
        return self.conn_cfn.describe_stack_events(stack_id)[0]

    def get_stack_instances(self, stack_name_or_id):
        # get the stack
        stack = self.conn_cfn.describe_stacks(stack_name_or_id)
        if not stack:
            print 'Empty stack'
            return []
        fn = lambda x: x.resource_type == 'AWS::AutoScaling::AutoScalingGroup'
        # get the scaling group
        scaling_group = filter(fn, stack[0].list_resources())
        if not scaling_group:
            print 'No scaling group found'
            return []
        scaling_group_id = scaling_group[0].physical_resource_id
        asc = autoscale.connect_to_region(self.config.aws_region,
                                          aws_access_key_id=self.config.aws_access,
                                          aws_secret_access_key=self.config.aws_secret)
        # get the instance IDs for all instances in the scaling group
        instances = asc.get_all_groups(names=[scaling_group_id])[0].instances
        return instances

    def get_stack_instance_ids(self, stack_name_or_id):
        return [
            x.instance_id for x in self.get_stack_instances(stack_name_or_id)]

    def stack_missing(self, stack_name):
        ''' Returns True if stack not found'''
        stacks = self.conn_cfn.describe_stacks()
        return stack_name not in [s.stack_name for s in stacks]

    def wait_for_stack_missing(self, stack_id, timeout=3600, interval=30):
        return utils.timeout(timeout, interval)(self.stack_missing)(stack_id)
