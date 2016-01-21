import logging

import time

import boto.ec2.elb

from boto.exception import BotoServerError

import boto.iam

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

    def set_ssl_certificates(self, cert_names, stack_name, max_retries=1, retry_delay=10):
        """
        Look for SSL listeners on all the load balancers connected to
        this stack, then set update the certificate to that of the config.
        We can retry with delay, default is to only try once.

        Args:
            ssl_config (dictionary): Certification names to corresponding data
            stack_name (string): Name of the stack
            max_retries(int): The number of retries to carry out on the operation
            retry_delay(int): The retry delay of the operation

        Returns:
            list: The list of the certificates that were replaced

        Raises:
            CloudResourceNotFoundError: Raised when the load balancer key in the cloud
                config is not found
        """
        # List of all certificates replaced
        replaced_certificates = []
        for cert_name in cert_names:
            # Get the cert id and also its arn
            cert_id = "{0}-{1}".format(cert_name, stack_name)
            cert_arn = self.iam.get_arn_for_cert(cert_id)

            # Get all stack load balancers
            load_balancer_resources = self.cfn.get_stack_load_balancers(stack_name)
            found_load_balancer_names = [lb["PhysicalResourceId"] for lb in load_balancer_resources]
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
                        in_port = listener[0]
                        protocol = listener[2]
                        # If the protocol is HTTPS then set the cert on the listener
                        if protocol == "HTTPS":
                            logging.info("ELB::set_ssl_certificates: "
                                         "Found HTTPS protocol on '%s', "
                                         "updating SSL certificate with '%s'"
                                         % (load_balancer.name, cert_arn))
                            # Get current listener certificate arn
                            previous_cert_arn = None
                            lb = self.conn_elb.get_all_load_balancers(load_balancer.name)[0]
                            for listener in lb.listeners:
                                # We're looking for a tuple of the form (443, 80, 'HTTPS', 'HTTP', <cert_arn>)
                                if 'HTTPS' in listener.get_tuple():
                                    previous_cert_arn = listener[4]
                            # Set the current certificate on the listener to the new one
                            retries = 0
                            while retries < max_retries:
                                retries += 1
                                try:
                                    self.conn_elb.set_lb_listener_SSL_certificate(load_balancer.name,
                                                                                  in_port,
                                                                                  cert_arn)
                                    if previous_cert_arn:
                                        previous_cert_name = previous_cert_arn.split('/')[1].split("-%s" % stack_name)[0]
                                        replaced_certificates.append(previous_cert_name)

                                    logging.info("update_certs:Successfully set ssl cert to '%s', "
                                                 " replacing cert '%s'"
                                                 % (cert_arn, previous_cert_name))

                                    break
                                except BotoServerError as e:
                                    logging.warning("update_certs: Cannot set ssl certs, reason '%s', "
                                                    "waiting %s seconds on retry %s/%s"
                                                    % (e.error_message, retry_delay, retries, max_retries))
                                    # Only sleep if we're going to try again
                                    if retries < max_retries:
                                        time.sleep(retry_delay)
            else:
                # Throw key error. There being no load balancers to update is not
                # necessarily a problem but since the caller expected there to be let
                # it handle this situation
                raise CloudResourceNotFoundError("ELB::set_ssl_certificates: "
                                                 "No load balancers found in stack,")

        return replaced_certificates

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
