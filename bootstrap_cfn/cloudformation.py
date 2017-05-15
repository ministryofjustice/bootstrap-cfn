import boto.cloudformation

import boto3

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

    def update(self, stack_name, template_body):
        try:
            stack = self.conn_cfn.update_stack(stack_name=stack_name,
                                               template_body=template_body,
                                               capabilities=['CAPABILITY_IAM'])
        except boto.exception.BotoServerError:
            return None

        return stack

    def delete(self, stack_name):
        stack = self.conn_cfn.delete_stack(stack_name)
        return stack

    def stack_done(self, stack_id):
        stack_events = self.conn_cfn.describe_stack_events(stack_id)
        if stack_events[0].resource_type == 'AWS::CloudFormation::Stack'\
                and stack_events[0].resource_status in ['CREATE_COMPLETE', 'CREATE_FAILED', 'ROLLBACK_COMPLETE', 'UPDATE_COMPLETE']:
            return True
        return False

    def stack_delete_done(self, stack_id):
        stack_events = self.conn_cfn.describe_stack_events(stack_id)
        if stack_events[0].resource_type == 'AWS::CloudFormation::Stack'\
                and stack_events[0].resource_status in ['DELETE_COMPLETE', 'DELETE_FAILED']:
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
        return get_resource_type(stack_name_or_id, resource_type)

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


def get_resource_type(stack_name_or_id,
                      resource_type=None):
    """
    Collect up a set of specific stack resources

    Args:
        stack_name_or_id (string): Name or id used to identify the stack
        resource_type(string): The resource type identifier

    Returns:
        resources: Set of stack resources containing only
            the resource type for this stack
    """
    client = boto3.client('cloudformation')
    all_resources = client.describe_stack_resources(StackName=stack_name_or_id)
    resources = [resource for resource in all_resources['StackResources'] if resource['ResourceType'] == resource_type]
    return resources


def get_stack_ids_by_name(stack_name_search_term):
    """
    Collect up a set of specific stacks matching a search term

    Args:
        stack_name_search_term (string): Search term used to identify the stack

    Returns:
        stack_ids: Set of stack ids containing only
            the stacks matching the search term.
    """
    client = boto3.client('cloudformation')
    all_stacks = client.describe_stacks()
    stacks = [stack for stack in all_stacks['Stacks'] if stack_name_search_term in stack['StackId']]
    return stacks


def get_all_stacks_by_attribute(attribute=None):
    """
    Get all the stacks in this connection
    Handle the pagination of results to make sure we get them all
    Return the specific attribute of stacks for example StackName
    Or the stack object if attribute=None

    Args:
        attribute (string): the attribute of stacks, e.g StackName or StackId

    Returns:
        all stacks with the attribute list, for example stack name list
    """
    client = boto3.client('cloudformation')
    response = client.describe_stacks()
    all_stacks = response.get('Stacks', None)
    while response.get('NextToken', None):
        response = client.describe_stacks(NextToken=response.get('NextToken', None))
        all_stacks += response.get('Stacks', None)
    if attribute is not None:
        return [stack.get(attribute) for stack in all_stacks]
    else:
        return all_stacks
