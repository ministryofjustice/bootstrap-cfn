import boto.cloudformation
import boto.ec2

from bootstrap_cfn import utils


class Cloudformation:

    conn_cfn = None
    aws_region_name = None
    aws_profile_name = None

    def __init__(self, aws_profile_name, aws_region_name='eu-west-1'):
        self.aws_profile_name = aws_profile_name
        self.aws_region_name = aws_region_name
        self.conn_cfn = utils.connect_to_aws(boto.cloudformation, self)

    def create(self, stack_name, template_body, tags):
        stack = self.conn_cfn.create_stack(stack_name=stack_name,
                                           template_body=template_body,
                                           capabilities=['CAPABILITY_IAM'],
                                           tags=tags)
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

    def stack_missing(self, stack_name):
        ''' Returns True if stack not found'''
        stacks = self.conn_cfn.describe_stacks()
        return stack_name not in [s.stack_name for s in stacks]

    def wait_for_stack_missing(self, stack_id, timeout=3600, interval=30):
        return utils.timeout(timeout, interval)(self.stack_missing)(stack_id)

    def get_stack_load_balancers(self, stack_name_or_id):
        """
        Collect up the load balancer set of stack resources

        Args:
            stack_name_or_id (string): Name or id used to identify the stack

        Returns:
            load_balancers: Set of stack resources containing only
                load balancers for this stack
        """
        resource_type = 'AWS::ElasticLoadBalancing::LoadBalancer'
        return self.get_resource_type(stack_name_or_id, resource_type)

    def get_resource_type(self, stack_name_or_id, resource_type=None):
        """
        Collect up a set of specific stack resources

        Args:
            stack_name_or_id (string): Name or id used to identify the stack
            resource_type(string): The resource type identifier

        Returns:
            resources: Set of stack resources containing only
                the resource type for this stack
        """
        # get the stack
        resources = []
        stack = self.conn_cfn.describe_stacks(stack_name_or_id)
        if stack:
            resources = stack[0].list_resources()
            if resource_type:
                # get the resources
                resources = filter(lambda x: x.resource_type == resource_type,
                                   resources)
        return resources
