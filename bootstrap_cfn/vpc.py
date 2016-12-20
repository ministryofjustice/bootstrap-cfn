import logging

import time

import boto3

from botocore.exceptions import ClientError

import netaddr

from bootstrap_cfn import cloudformation

from bootstrap_cfn.errors import CloudResourceNotFoundError


class VPC:
    """
    Class used to work with stack VPC's. It allows the peering of
    VPC's through the use of configuration data on target stacks
    """
    # Configuration data
    stack_name = None
    config = None
    vpc_config = {}
    # Dictionary of stack peering configuration details. eg
    # <stack_search_name> : {
    #    stack_id: <stack_id>,
    #    routes: {
    #        <route_table_logical_id>: [
    #                <cidr_block_a>,
    #                <cidr_block_b>
    #        ]
    #    }
    peering_config = {}

    # Stacks vpc id
    vpc_id = None

    logger = None

    def __init__(self, config_data, stack_name):
        """
        Default initialiser

        Args:
            config_data(dict): The cloudformation configuration data
            stack_name(string): The name of the current stack
        """
        # Setup logging
        self.setup_logging()
        self.peering_config = self.parse_config(config_data, stack_name)

    def disable_peering(self,
                        peering_stack_search_name=None):
        """
        Disable VPC peering to stacks

        Args:
            peering_stack_search_name(string): The search stack name for the peering stack. Since
                stack names have a randomised element this allows us to adapt and
                target the same stack even when its recreated.
        """
        if not peering_stack_search_name:
            for peering_stack_config in self.peering_config.values():
                self.delete_peering_connections(peering_stack_search_name)
                self.delete_peering_routes(peering_stack_config)
        else:
            self.delete_peering_connections(peering_stack_search_name)
            self.delete_peering_routes(self.peering_config.get(peering_stack_search_name))

    def enable_peering(self,
                       peering_stack_search_name=None):
        """
        Peer stacks with this one

        Args:
            peering_stack_search_name(string): The search stack name for the peering stack. Since
                stack names have a randomised element this allows us to adapt and
                target the same stack even when its recreated.
        """
        if not peering_stack_search_name:
            for peering_stack, peering_stack_config in self.peering_config.iteritems():
                stack_name = peering_stack_config['stack_name']
                self.peer_to_stack(stack_name)
        else:
            self.peer_to_stack(peering_stack_search_name)

    def peer_to_stack(self,
                      peering_stack_name):
        """
        Create a peering connection to the names stack and create routes between
        peered vpcs in their respective default route tables

        Args:
            peering_stack_name(string): The name of the stack to peer this one to
            peering_stack_config(dict): Dictionary of configuration options for
                this peering connection
        """
        peering_stack_configs = [config for key, config in self.peering_config.iteritems() if config['stack_name'] == peering_stack_name]
        if len(peering_stack_configs) == 0:
            raise Exception
        peering_stack_config = peering_stack_configs[0]
        ec2_resource = boto3.resource('ec2')
        #  PeerOwnerId='string' can be set for peering different accoutns
        vpc_peering_connection = ec2_resource.create_vpc_peering_connection(
            VpcId=self.vpc_id,
            PeerVpcId=peering_stack_config['vpc_id'],
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
        # pee
        self.create_peering_routes(vpc_peering_connection,
                                   peering_stack_config)
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
                              peering_conn,
                              peering_stack_config):
        """
        Create the routes from this stack to the peering stack and
        vice versa. By default we will route all CIDR in each peered
        VPC

        Args:
            peering_conn(VPCPeeringConnection): The peering connection to route
                to route to and from
            peering_stack_config(dict): The configuration of the peering connection
                to setup
        """
        source_route_tables = peering_stack_config.get('source_routes')
        for route_table_key, route_table_config in source_route_tables.iteritems():
            cidr_blocks = route_table_config.get('cidr_blocks')
            for cidr_block in cidr_blocks:
                self.create_route_vpc_to_vpc_peer(
                    vpc_id=peering_conn.requester_vpc_info['VpcId'],
                    target_vpc_cidr=cidr_block,
                    peering_conn_id=peering_conn.id,
                    route_table_ids=[route_table_config['route_table_id']]
                )
        target_route_tables = peering_stack_config.get('target_routes')
        for route_table_key, route_table_config in target_route_tables.iteritems():
            cidr_blocks = route_table_config.get('cidr_blocks')
            for cidr_block in cidr_blocks:
                self.create_route_vpc_to_vpc_peer(
                    vpc_id=peering_conn.accepter_vpc_info['VpcId'],
                    target_vpc_cidr=cidr_block,
                    peering_conn_id=peering_conn.id,
                    route_table_ids=[route_table_config['route_table_id']],
                )

    def delete_peering_routes(self, peering_config):
        """
        Deletes the VPC peering routes from source and target vpcs. This
        will match anything in stack_search_name up to the target limit

        Args:
            peering_config(dict): The config of the peering connection
        """
        for route_set in ['source_routes', 'target_routes']:
            route_configs = peering_config.get(route_set, {}).values()
            for route_config in route_configs:
                self.delete_routes_from_tables(
                    route_table_id=route_config['route_table_id'],
                    cidr_blocks=route_config['cidr_blocks']
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

    def get_vpc_cidr_blocks(
            self,
            vpc_id):
        """
        Get a vpcs cidr range

        Args:
            vpc(string): The vpc id to get the cidrs for
        Returns:
            (list): The cidr range of the VPC
        """
        ec2_resource = boto3.resource('ec2')
        vpc = ec2_resource.Vpc(vpc_id)
        return [vpc.cidr_block]

    def create_route_vpc_to_vpc_peer(self,
                                     vpc_id,
                                     target_vpc_cidr,
                                     peering_conn_id,
                                     route_table_ids):
        """
        Create a specified cidr route from all route_tables in a VPC
        through a peering connection.

        Args:
            vpc_id(string): The id of the vpc to remove routes from
            target_vpc_cidr(string): The cidr of the route to remove
            peering_connection(string): The id of the peering connection
            route_table_ids(list): The list of route table ids
                to setup the route on. If None, setup on all route tables.
        """
        ec2_client = boto3.client('ec2')
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

    def delete_routes_from_tables(
            self,
            route_table_id,
            cidr_blocks):
        """
        Delete a specified cidr from all route_tables in a VPC

        Args:
            route_table_id(string): The route table id to delete the
                cidr blocks from
            cidr_blocks(list): The list of cidrs to remove from the
                route table
        """
        ec2_client = boto3.client('ec2')
        for cidr_block in cidr_blocks:
            try:
                ec2_client.delete_route(
                    RouteTableId=route_table_id,
                    DestinationCidrBlock=cidr_block
                )
                self.logger.info(
                    "vpc::delete_routes_from_tables: "
                    "Deleted cidr block '%s' from route '%s'"
                    % (cidr_block, route_table_id)
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidRoute.NotFound':
                    msg = (
                        "vpc::delete_routes_from_tables: No route '%s' "
                        " found in table '%s'"
                        % (cidr_block, route_table_id))
                    self.logger.warn(msg)
                else:
                    raise e

    def setup_logging(self):
        logging.getLogger('boto3').setLevel(logging.CRITICAL)
        logging.getLogger('botocore').setLevel(logging.CRITICAL)
        self.logger = logging.getLogger('bootstrap_cfn')
        self.logger.setLevel(logging.INFO)

    def parse_config(self,
                     config_data,
                     stack_name):
        """
        Setup the config environment

        Args:
            config_data(dict): The cloudformation configuration data
            stack_name(string): The name of the current stack
        """
        self.stack_name = stack_name
        self.config_data = config_data
        self.vpc_config = self.config_data.get('vpc', {})
        self.vpc_id = self.get_stack_vpc_id(stack_name)

        peering_config = self.vpc_config.get('peering', {})
        parsed_peering_config = {}

        for peering_stack_search_name, peering_stack_config_entry in peering_config.iteritems():
            # Make sure we match to one and only one stack
            found_stacks = self.get_stack_name_by_match(peering_stack_search_name, min_results=1, max_results=1)

            if found_stacks:
                peering_stack_name = found_stacks[0]['StackName']
                peering_stack_vpc_id = self.get_stack_vpc_id(peering_stack_name)
                self.logger.info("vpc::parse_config: Found stack '%s' with vpc '%s'"
                                 % (peering_stack_search_name, peering_stack_vpc_id))
                # Setup layout for stack peering config
                parsed_peering_config[peering_stack_search_name] = {}
                parsed_peering_config[peering_stack_search_name]['source_routes'] = {}
                parsed_peering_config[peering_stack_search_name]['target_routes'] = {}
                parsed_peering_config[peering_stack_search_name]['stack_name'] = peering_stack_name
                parsed_peering_config[peering_stack_search_name]['vpc_id'] = peering_stack_vpc_id

                # Expand all wildcards recursively
                # If the entry is wildcarded then peer the vpcs cidr blocks to all route_tables
                if peering_config[peering_stack_search_name] == '*':
                    self.logger.info("vpc::parse_config: Found stack wildcard, matching all routes and addresses...")
                    peering_config[peering_stack_search_name] = {}
                    peering_config[peering_stack_search_name]['source_routes'] = '*'
                    peering_config[peering_stack_search_name]['target_routes'] = '*'

                # If the route set is wildcarded then apply the cidr_blocks to all route tables
                # source_routes: '*'
                route_config_dictionary = {
                    'source_routes': {'route_tables_vpc_id': self.vpc_id, 'cidr_blocks_vpc_id': peering_stack_vpc_id},
                    'target_routes': {'route_tables_vpc_id': peering_stack_vpc_id, 'cidr_blocks_vpc_id': self.vpc_id}
                }

                for route_set, routes_vpc_config in route_config_dictionary.iteritems():
                    route_tables_vpc_id = routes_vpc_config['route_tables_vpc_id']
                    cidr_blocks_vpc_id = routes_vpc_config['cidr_blocks_vpc_id']
                    if peering_config[peering_stack_search_name][route_set] == '*':
                        self.logger.info("vpc::parse_config: Found %s wildcard, matching all %s routes and addresses..."
                                         % (route_set, route_set))
                        all_vpc_cidr_blocks = self.get_vpc_cidr_blocks(cidr_blocks_vpc_id)
                        for vpc_route_table_id in self.get_vpc_route_table_ids(route_tables_vpc_id):
                            parsed_peering_config[peering_stack_search_name][route_set][vpc_route_table_id] = {}
                            parsed_peering_config[peering_stack_search_name][route_set][vpc_route_table_id]['route_table_id'] = vpc_route_table_id
                            parsed_peering_config[peering_stack_search_name][route_set][vpc_route_table_id]['cidr_blocks'] = all_vpc_cidr_blocks
                    else:
                        for route_table_name, route_table_config in peering_config[peering_stack_search_name].get(route_set, {}).iteritems():
                            if route_table_config['cidr_blocks'] == '*':
                                self.logger.info("vpc::parse_config: Found cidr block wildcard, using '%s' for route table %s..."
                                                 % (cidr_blocks_vpc_id, route_table_name))
                                cidr_blocks = self.get_vpc_cidr_blocks(cidr_blocks_vpc_id)
                            else:
                                cidr_blocks = route_table_config['cidr_blocks']

                            if route_table_name == '*':
                                self.logger.info("vpc::parse_config: Found route table wildcard, "
                                                 "applying cidr blocks to all %s route tables..."
                                                 % (route_set))
                                for vpc_route_table_id in self.get_vpc_route_table_ids(route_tables_vpc_id):
                                    parsed_peering_config[peering_stack_search_name][route_set][vpc_route_table_id] = {}
                                    parsed_peering_config[peering_stack_search_name][route_set][vpc_route_table_id]['route_table_id'] = vpc_route_table_id
                                    parsed_peering_config[peering_stack_search_name][route_set][vpc_route_table_id]['cidr_blocks'] = cidr_blocks
                            else:
                                parsed_peering_config[peering_stack_search_name][route_set][route_table_name] = {}
                                parsed_peering_config[peering_stack_search_name][route_set][route_table_name]['route_table_id'] = (
                                    self.get_vpc_route_table_ids(peering_stack_vpc_id, route_table_name)[0]
                                )
                                parsed_peering_config[peering_stack_search_name][route_set][route_table_name]['cidr_blocks'] = cidr_blocks
            else:
                self.logger.error("vpc::setup_config: Not stack found that matches search term '%s'"
                                  % (peering_stack_search_name))
                raise CloudResourceNotFoundError

        return parsed_peering_config

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


def get_available_cidr_block(cidr_prefix,
                             subnet_prefix=28,
                             available_addresses=None):
    """
    Get the first unused available VPC CIDR block plus the
    available subnets

    Args:
        cidr_prefix(int): The cidr prefix to the main vpc address block
        subnet_prefix(int): The cidr prefix to the main vpc address subnet blocks
        available_addresses(IPSet): The set of address blocks to subnet, if None,
            these will be generated dynamically from available address ranges in
            the VPC.

    Returns:
        (string): The main vpc address block, None if not found
        (list): The main vpc address block subnets, None if not found
    """
    if available_addresses is None:
        logger.info("get_available_cidr_blocks: No available address list provided, "
                    "requesting available VPC address list from AWS...")
        available_addresses = get_available_addresses()
    else:
        logger.info("get_available_cidr_blocks: Using available address list provided...")

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
