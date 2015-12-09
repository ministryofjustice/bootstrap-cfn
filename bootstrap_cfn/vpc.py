import logging

import boto3

import netaddr

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
