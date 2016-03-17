import boto3

from netaddr import IPNetwork, AddrFormatError, AddrConversionError


class ElasticIP:

    client = None

    def __init__(self):
        self.client = boto3.client('ec2')

    def associate_eip(self,
                      instance_id,
                      public_ip,
                      private_ip,
                      allow_reassociation=True):
        """
        Associate a public/private ip address to an instance
        """
        response = vpc_address.associate(
            InstanceId=instance_id,
            PublicIp=public_ip,
            PrivateIpAddress='string',
            AllowReassociation=allow_reassociation
        )
        response = vpc_address.associate(
            InstanceId=instance_id,
            PrivateIpAddress=private_ip,
            AllowReassociation=allow_reassociation
        )

    def disassociate_eip(self,
                        instance_id,
                        public_ip,
                        private_ip):
        """
        """
        response = vpc_address.release(
            PublicIp=public_ip)

    def _get_unassociated_address(self, ip_addresses):
        """ Return the first unassociated address we can find

        :returns: boto.ec2.address or None
        """
        eip = None
        for address in self.client.get_all_addresses():
            # Check if the address is associated
            if address.instance_id:
                self.logger.debug('{0} is already associated with {1}'.format(
                    address.public_ip, address.instance_id))
                continue
            # Check if the address is in the valid IP's list
            if self._is_valid(address.public_ip):
                self.logger.debug('{0} is unassociated and OK for us to take'.format(
                    address.public_ip))
                eip = address
                break
            else:
                self.logger.debug(
                    '{0} is unassociated, but not in the valid IPs list'.format(
                        address.public_ip, address.instance_id))

        if not eip:
            self.logger.error('No unassociated Elastic IP found!')

        return eip
