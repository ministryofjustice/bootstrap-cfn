import logging

import boto.ec2.elb

from bootstrap_cfn import cloudformation, iam, utils
from bootstrap_cfn.errors import BootstrapCfnError, CloudResourceNotFoundError


class ELB:

    cfn = None
    iam = None
    aws_region_name = None
    aws_profile_name = None

    def __init__(self, aws_profile_name, aws_region_name='eu-west-1'):
        self.aws_profile_name = aws_profile_name
        self.aws_region_name = aws_region_name

        self.conn_elb = utils.connect_to_aws(boto.ec2.elb, self)

        self.iam = iam.IAM(aws_profile_name, aws_region_name)
        self.cfn = cloudformation.Cloudformation(
            aws_profile_name, aws_region_name
        )

    def set_ssl_certificates(self, ssl_config, stack_name):
        """
        Look for SSL listeners on all the load balancers connected to
        this stack, then set update the certificate to that of the config

        Args:
            ssl_config (dictionary): Certification names to corresponding data
            stack_name (string): Name of the stack

        Returns:
            list: The list of load balancers that were affected by the change

        Raises:
            CloudResourceNotFoundError: Raised when the load balancer key in the cloud
                config is not found
        """
        updated_load_balancers = []
        for cert_name in ssl_config.keys():
            # Get the cert id and also its arn
            cert_id = "{0}-{1}".format(cert_name, stack_name)
            cert_arn = self.iam.get_arn_for_cert(cert_id)

            # Get all stack load balancers
            load_balancer_resources = self.cfn.get_stack_load_balancers(stack_name)
            found_load_balancer_names = [lb.physical_resource_id for lb in load_balancer_resources]
            # Use load balancer names to filter getting load balancer details
            load_balancers = []
            if len(found_load_balancer_names) > 0:
                load_balancers = self.conn_elb.get_all_load_balancers(load_balancer_names=found_load_balancer_names)

            # Look for https listeners on load balancers and update the cert
            # using the arn
            if len(load_balancers) > 0:
                for load_balancer in load_balancers:
                    for listener in load_balancer.listeners:
                        # Get protocol, if https, update cert
                        # in_port = listener[0]
                        out_port = listener[1]
                        protocol = listener[2]
                        # If the protocol is HTTPS then set the cert on the listener
                        if protocol == "HTTPS":
                            logging.info("ELB::set_ssl_certificates: "
                                         "Found HTTPS protocol on '%s', "
                                         "updating SSL certificate with '%s'"
                                         % (load_balancer.name, cert_arn))
                            self.conn_elb.set_lb_listener_SSL_certificate(load_balancer.name,
                                                                          out_port,
                                                                          cert_arn
                                                                          )
                            updated_load_balancers.append(load_balancer)

            else:
                # Throw key error. There being no load balancers to update is not
                # necessarily a problem but since the caller expected there to be let
                # it handle this situation
                raise CloudResourceNotFoundError("ELB::set_ssl_certificates: "
                                                 "No load balancers found in stack,")

        return updated_load_balancers

    def list_domain_names(self, stack_name):
        """
        Return a list of dicts, each containing the ELB name and corresponding DNS Name for
        each ELB in a given environment.

        Args:
            stack name

        Returns:
            list of dict: [{'elb_name': string, 'dns_name': string}]

        Raises:
            The boto call raises self.ResponseError(response.status, response.reason, body)
            if the AWS call returns an error, for example if the ELB name does not exist
        """
        lb_name_dns = []
        load_balancer_resources = self.cfn.get_stack_load_balancers(stack_name)
        lb_ids = [l.physical_resource_id for l in load_balancer_resources]
        if not lb_ids:
            raise BootstrapCfnError("No ELBs found for stack %s" % stack_name)
        lbs_details = self.conn_elb.get_all_load_balancers(load_balancer_names=lb_ids)
        if not lbs_details:
            raise BootstrapCfnError("No ELBs details returned by AWS")
        lb_name_dns = [{'elb_name': l.name, 'dns_name': l.dns_name} for l in lbs_details]
        return lb_name_dns
