import logging

import time

import boto3

from botocore.exceptions import ClientError

from bootstrap_cfn import cloudformation

import netaddr


class VPC:
    """
    Class used to work with stack VPC's. It allows the peering of
    VPC's through the use of configuration data on target stacks
    """
    # Configuration data
    config = None
    vpc_config = {}
    peering_config = {}

    # Stacks vpc id
    vpc_id = None

    logger = None

    def __init__(self, config, stack_name):
        """
        Default initialiser

        Args:
            cfg(dict): The cloudformation configuration data
            stack_name(string): The name of the current stack
        """
        # Setup logging
        logging.getLogger('boto3').setLevel(logging.CRITICAL)
        logging.getLogger('botocore').setLevel(logging.CRITICAL)
        self.logger = logging.getLogger('bootstrap_cfn')
        self.logger.setLevel(logging.INFO)
        self.config = config
        self.vpc_config = self.config.data.get('vpc', {})
        self.peering_config = self.vpc_config.get('peering', {})
        self.vpc_id = self.get_stack_vpc_id(stack_name)

    def disable_peering(self,
                        stack_name=None,
                        target_limit=1):
        """
        Disable VPC peering to stacks

        Args:
            stack_name(string): The search stack name for the peering stack. Since
                stack names have a randomised element this allows us to adapt and
                target the same stack even when its recreated.
            target_limit(int): Set the number of peering target stacks we should limit
                our matches to.
        """
        if not stack_name:
            for peer_stack in self.peering_config.keys():
                found_stacks = self.get_stack_name_by_match(peer_stack, min_results=1, max_results=target_limit)
                if found_stacks:
                    for found_stack in found_stacks:
                        stack_name = found_stack.get('StackName')
                        self.delete_peering_routes(stack_name)
                        self.delete_peering_connections(stack_name, target_limit=1)
        else:
            self.delete_peering_connections(stack_name)

    def enable_peering(self,
                       stack_name=None,
                       target_limit=1):
        """
        Peer stacks with this one

        Args:
            stack_name(string): The search stack name for the peering stack. Since
                stack names have a randomised element this allows us to adapt and
                target the same stack even when its recreated.
            target_limit(int): Set the number of peering target stacks we should limit
                our matches to.
        """
        if not stack_name:
            for peer_stack in self.peering_config.keys():
                found_stacks = self.get_stack_name_by_match(peer_stack, min_results=1, max_results=target_limit)
                if found_stacks:
                    for found_stack in found_stacks:
                        stack_name = found_stack.get('StackName')
                        self.peer_to_stack(stack_name)
        else:
            self.peer_to_stack(stack_name)

    def peer_to_stack(self,
                      peer_stack_name):
        """
        Create a peering connection to the names stack and create routes between
        peered vpcs in their respective default route tables

        Args:
            peer_stack_name(string): The name of the stack to peer this one to
        """

        peer_vpc_id = self.get_stack_vpc_id(peer_stack_name)
        if not peer_vpc_id:
            self.logger.error("VPC::peer_to_stack: Unique vpc not found for stack '%s'"
                              % (peer_stack_name))
            return False

        ec2_resource = boto3.resource('ec2')
        #  PeerOwnerId='string' can be set for peering different accoutns
        vpc_peering_connection = ec2_resource.create_vpc_peering_connection(
            VpcId=self.vpc_id,
            PeerVpcId=peer_vpc_id,
        )
        self.logger.info("VPC::peer_to_stack: Creating peering connection '%s'"
                         % (vpc_peering_connection.id))

        # Have the peer target stack accept the peering
        ec2_client = boto3.client('ec2')
        ec2_client.accept_vpc_peering_connection(
            VpcPeeringConnectionId=vpc_peering_connection.id
        )
        self.logger.info("VPC::peer_to_stack: Accepting peering connection '%s'"
                         % (vpc_peering_connection.id))
        # wait for required state
        self.wait_for_connection_states(
            vpc_peering_connection,
            status_codes=['pending-acceptance', 'provisioning', 'active'])
        # setup routes
        self.logger.info("VPC::peer_to_stack: Creating peering routes...")
        self.create_peering_routes(vpc_peering_connection)
        # setup ACL
        # TODO

    def wait_for_connection_states(self,
                                   peering_conn,
                                   status_codes=['active'],
                                   timeout=15):
        """
        Wait for a peering connection to enter a specified state within
        a timeout period

        Args:
            peering_conn(VPCPeeringConnection): The peering connection to monitor
            status_codes(list): List of status codes to wait on
            timeout(int): The timeout period in seconds to wait before giving up
        """
        wait_end = time.time() + timeout
        while wait_end > time.time():
            peering_conn.reload()
            if peering_conn.status['Code'] in status_codes:
                return True

            time.sleep(1)
        return False

    def create_peering_routes(self,
                              peering_conn):
        """
        Create the routes from this stack to the peering stack and
        vice versa. By default we will route all CIDR in each peered
        VPC

        Args:
            peering_conn(VPCPeeringConnection): The peering connection to route
                to route to and from
        """
        self.create_route_vpc_to_vpc_peer(
            vpc_id=peering_conn.requester_vpc_info['VpcId'],
            target_vpc_cidr=peering_conn.accepter_vpc_info['CidrBlock'],
            peering_conn_id=peering_conn.id
        )
        self.create_route_vpc_to_vpc_peer(
            vpc_id=peering_conn.accepter_vpc_info['VpcId'],
            target_vpc_cidr=peering_conn.requester_vpc_info['CidrBlock'],
            peering_conn_id=peering_conn.id
        )

    def delete_peering_routes(self, stack_search_name, target_limit=1):
        """
        Deletes the VPC peering routes from source and target vpcs. This
        will match anything in stack_search_name up to the target limit

        Args:
            stack_search_name(string): The search name of the peered stacks
            target_limit(int): The limit on the number of stack search results
        """
        peering_conns = self.get_stack_peering_connections(stack_search_name)

        if not peering_conns:
            self.logger.error("vpc::delete_peering_routes: "
                              "Peering_connections for stack id '%s' not found"
                              % stack_search_name)
            return False

        if len(peering_conns) > target_limit:
            self.logger.error("vpc::delete_peering_routes: "
                              "Too many peering connection matches for stack name '%s'"
                              % stack_search_name)
            return False

        for peering_conn in peering_conns:
            self.delete_route_vpc_to_vpc_peer(
                vpc_id=peering_conn.requester_vpc_info['VpcId'],
                target_vpc_cidr=peering_conn.accepter_vpc_info['CidrBlock']
            )
            self.delete_route_vpc_to_vpc_peer(
                vpc_id=peering_conn.accepter_vpc_info['VpcId'],
                target_vpc_cidr=peering_conn.requester_vpc_info['CidrBlock']
            )

    def delete_peering_connections(
        self,
        stack_search_name,
        target_limit=1
    ):
        """
        Deletes a VPC peering connection

        Args:
            stack_search_name(string): The search name of the peered stacks
            target_limit(int): The limit on the number of stack search results
        """
        peering_conns = self.get_stack_peering_connections(stack_search_name)

        if not peering_conns:
            self.logger.error("vpc::delete_peering_connections: "
                              "Peering_connections for stack id '%s' not found"
                              % stack_search_name)
            return False

        if len(peering_conns) > target_limit:
            self.logger.error("vpc::delete_peering_connections: "
                              "Too many peering connections matches for stack name '%s'"
                              % stack_search_name)
            return False

        for peering_conn in peering_conns:
            if not peering_conn.delete():
                self.logger.error("vpc::delete_peering_connections: "
                                  "Error deleting peering connection to stack '%s'"
                                  % stack_search_name)

        return True

    def get_stack_peering_connections(self, stack_name, status_codes=['active']):
        """
        Get all of the peering connections withing a stack that have the specified status

        Args:
            stack_name(string): The name of the stack
            status_codes(list): The list of status codes to filter the peering connection on.
                Possible values are pending-acceptance, failed, expired, provisioning, active, deleted, rejected

        Returns:
            (list): The VPCPeeringConnections belonging to the specified stack
        """
        ec2_client = boto3.client('ec2')
        ec2_resource = boto3.resource('ec2')
        peering_connections = []
        peering_connection_filter = [{'Name': 'requester-vpc-info.vpc-id', 'Values': [self.vpc_id]}]
        if status_codes:
            peering_connection_filter.append({'Name': 'status-code', 'Values': status_codes})
        if stack_name:
            peer_stack_vpc_id = self.get_stack_vpc_id(stack_name)
            if peer_stack_vpc_id:
                peering_connection_filter.append({'Name': 'accepter-vpc-info.vpc-id', 'Values': [peer_stack_vpc_id]})

        # Get all peering connections
        peering_conn_descriptions = ec2_client.describe_vpc_peering_connections(Filters=peering_connection_filter)

        for peering_conn_description in peering_conn_descriptions.get('VpcPeeringConnections', []):
            peering_conn_id = peering_conn_description['VpcPeeringConnectionId']
            peering_connections.append(ec2_resource.VpcPeeringConnection(peering_conn_id))

        return peering_connections

    def get_stack_route_table_ids(
            self,
            stack_name):
        """
        Get all the route tables for the specified stack name

        Args:
            stack_name(string): The name of the stack

        Returns:
            (list): The route tables belonging to the specified stack
        """
        resources = cloudformation.get_resource_type(stack_name, resource_type='AWS::EC2::RouteTable')
        if len(resources) < 1:
            self.logger.error("VPC::get_stack_route_tables: No route tables found for stack '%s'"
                              % (stack_name))
            return None
        return resources

    def get_stack_vpc_id(
            self,
            stack_name):
        """
        Get the unique VPC for the specified stack name

        Args:
            stack_name(string): The name of the stack

        Returns:
            (string): The PhysicalResourceId of the vpc, None if there are multiple
                or no vpcs found
        """
        vpcs = cloudformation.get_resource_type(stack_name, resource_type='AWS::EC2::VPC')
        if len(vpcs) > 1:
            self.logger.error("VPC::get_stack_vpc: Unique vpc not found for stack '%s'"
                              % (stack_name))
            return None
        elif len(vpcs) < 1:
            self.logger.error("VPC::get_stack_vpc: No vpc found for stack '%s'"
                              % (stack_name))
            return None
        return vpcs[0]['PhysicalResourceId']

    def get_stack_name_by_match(
            self,
            stack_search_name,
            min_results=1,
            max_results=1):
        """
        Get a set of stack names that match a search term.

        Args:
            stack_name(string): The name of the stack
            min_results(int): The minimum number of results to expect
            max_results(int): The maximum number of results to expect

        Returns:
            (list): The set of stack ids found
        """
        stack_ids = cloudformation.get_stack_ids_by_name(stack_search_name)

        if len(stack_ids) > max_results:
            self.logger.error("VPC::get_stack_name_by_match: "
                              "Found %s results, expected maximum %s for stack '%s'"
                              % (len(stack_ids), max_results, stack_search_name))
            return None
        elif len(stack_ids) < min_results:
            self.logger.error("VPC::get_stack_name_by_match: "
                              "Found %s results, expected minimum %s for stack '%s'"
                              % (len(stack_ids), max_results, stack_search_name))
            return None
        return stack_ids

    def get_vpc_route_table_ids(
            self,
            vpc_id,
            logical_id_filter=None,
            min_subnet_associations=None,
            is_main=None):
        """
        Get a filtered set of route table ids for a supplied vpc

        Args:
            (string): The vpc id to get the default route
                table for

        Returns:
            (list): The default route table id, None if
                it wasnt found
        """
        route_table_ids = []
        ec2_resource = boto3.resource('ec2')
        vpc = ec2_resource.Vpc(vpc_id)

        for route_table in list(vpc.route_tables.all()):
            if not logical_id_filter and not min_subnet_associations and not is_main:
                route_table_ids.append(route_table.id)
            else:
                if logical_id_filter:
                    filtered_tables = [
                        entry['Key'] for entry in route_table.tags if (
                            entry['Key'] == 'aws:cloudformation:logical-id' and entry['Value'] == logical_id_filter)
                    ]
                    if len(filtered_tables) > 0:
                        route_table_ids.append(route_table.id)

                if min_subnet_associations:
                    if (route_table.association > min_subnet_associations):
                        route_table_ids.append(route_table.id)

                if is_main:
                    for association in list(route_table.associations.all()):
                        if association.main is True:
                            route_table_ids.append(route_table.id)
        return route_table_ids

    def create_route_vpc_to_vpc_peer(self,
                                     vpc_id,
                                     target_vpc_cidr,
                                     peering_conn_id):
        """
        Create a specified cidr route from all route_tables in a VPC
        through a peering connection.

        Args:
            vpc_id(string): The id of the vpc to remove routes from
            target_vpc_cidr(string): The cidr of the route to remove
            peering_connection(string): The id of the peering connection
        """
        ec2_client = boto3.client('ec2')

        route_table_ids = self.get_vpc_route_table_ids(vpc_id, min_subnet_associations=0)
        for route_table_id in route_table_ids:
            try:
                self.logger.info("VPC::create_route_vpc_to_vpc_peer: Creating route in '%s'"
                                 " range '%s' through peering connection '%s'"
                                 % (route_table_id, target_vpc_cidr, peering_conn_id))
                ec2_client.create_route(
                    RouteTableId=route_table_id,
                    DestinationCidrBlock=target_vpc_cidr,
                    VpcPeeringConnectionId=peering_conn_id
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'RouteAlreadyExists':
                    msg = (
                        "vpc::route_vpc_to_vpc_peer: Adding routes to vpc, "
                        "route '%s' already exists in table '%s',"
                        " skipping creation"
                        % (target_vpc_cidr, route_table_id))
                    self.logger.warn(msg)
                else:
                    raise e

    def delete_route_vpc_to_vpc_peer(
            self,
            vpc_id,
            target_vpc_cidr):
        """
        Delete a specified cidr from all route_tables in a VPC

        Args:
            vpc_id(string): The id of the vpc to remove routes from
            target_vpc_cidr(string): The cidr of the route to remove
        """
        ec2_client = boto3.client('ec2')

        route_table_ids = self.get_vpc_route_table_ids(vpc_id, min_subnet_associations=0)
        for route_table_id in route_table_ids:
            try:
                ec2_client.delete_route(
                    RouteTableId=route_table_id,
                    DestinationCidrBlock=target_vpc_cidr
                )
                self.logger.info(
                    "vpc::delete_route_vpc_to_vpc_peer: "
                    "Deleted cidr block '%s' from route '%s'"
                    % (target_vpc_cidr, route_table_id)
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidRoute.NotFound':
                    msg = (
                        "vpc::delete_route_vpc_to_vpc_peer: No route '%s' "
                        " found in table '%s'"
                        % (target_vpc_cidr, route_table_id))
                    self.logger.warn(msg)
                else:
                    raise e

# Setup the logging
logger = logging.getLogger('vpc_available_addresses')
logger.setLevel(logging.INFO)
loghandler = logging.StreamHandler()
logger.addHandler(loghandler)


def get_available_addresses():
    """
    Get the unused networks CIDR for all vpcs in this account

    Returns:
        (list): List of available IPNetworks in CIDR notation
    """
    ec2_client = boto3.client('ec2')
    vpcs = ec2_client.describe_vpcs().get('Vpcs', [])
    vpc_cidr_mappings = {}
    for vpc in vpcs:
        vpc_cidr_mappings[vpc['VpcId']] = vpc['CidrBlock']

    private_ipv4_address_space = netaddr.IPSet(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
    used_ipv4_address_space = netaddr.IPSet(vpc_cidr_mappings.values())
    available_ipv4_address_space = private_ipv4_address_space ^ used_ipv4_address_space
    return available_ipv4_address_space


def get_available_cidr_block(cidr_prefix, subnet_prefix=28):
    """
    Get the first unused available VPC CIDR block plus the
    available subnets

    Args:
        cidr_prefix(int): The cidr prefix to the main vpc address block
        subnet_prefix(int): The cidr prefix to the main vpc address subnet blocks

    Returns:
        (string): The main vpc address block, None if not found
        (list): The main vpc address block subnets, None if not found
    """
    available_addresses = get_available_addresses()
    if len(available_addresses) > 0:
        # Find the first group that we can subnet succesfully
        for available_address_cidr in available_addresses.iter_cidrs():
            free_cidr_blocks = list(available_address_cidr.subnet(cidr_prefix))
            if len(free_cidr_blocks) > 0:

                free_cidr_block = free_cidr_blocks[0]
                subnet_cidr_blocks = list(free_cidr_block.subnet(subnet_prefix))

                free_cidr_blockstr = str(free_cidr_block)
                subnet_cidr_blocksstr = [str(cidr) for cidr in subnet_cidr_blocks]
                logger.info("get_available_cidr_blocks: Found free cidr block, '%s'"
                            " with subnets '%s'"
                            % (free_cidr_blockstr, subnet_cidr_blocksstr))
                return free_cidr_blockstr, subnet_cidr_blocksstr
            else:
                logger.info("get_available_cidr_blocks: Could not subnet CIDR '%s'"
                            % (available_address_cidr))
    return None, None