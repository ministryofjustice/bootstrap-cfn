import logging

import time

from boto.connection import AWSQueryConnection

from boto.exception import BotoServerError

import boto.iam

from bootstrap_cfn import utils


class IAM:

    conn_cfn = None
    aws_region_name = None
    aws_profile_name = None

    def __init__(self, aws_profile_name, aws_region_name='eu-west-1'):
        self.aws_profile_name = aws_profile_name
        self.aws_region_name = aws_region_name

        self.conn_iam = utils.connect_to_aws(boto.iam, self)

    def upload_ssl_certificate(self, ssl_config, stack_name):
        for cert_name, ssl_data in ssl_config.items():
            self.upload_certificate(cert_name,
                                    stack_name,
                                    ssl_data,
                                    force=True)
        return True

    def delete_ssl_certificate(self, ssl_config, stack_name):
        for cert_name, ssl_data in ssl_config.items():
            self.delete_certificate(cert_name,
                                    stack_name)
        return True

    def update_ssl_certificates(self, ssl_config, stack_name):
        """
        Update all the ssl certificates in the identified stack. Note,
        this creates a uniquely named ssl certificate and doesn't overwrite
        the current ones.

        Args:
            ssl_config(dictionary): A dictionary of ssl configuration data
                organised by cert_name to a dictionary with the config
                data in it
            stack_name(string): The name of the stack

        Returns:
            list: List of certificates that were successfully updated
        """
        updated_certificates = []
        for cert_name, ssl_data in ssl_config.items():
            try:
                # Generate uniquely timestamped certificate name and upload it
                timestamped_cert_name = ("%s-%s"
                                         % (cert_name, time.time()))
                upload_success = self.upload_certificate(timestamped_cert_name,
                                                         stack_name,
                                                         ssl_data,
                                                         force=True)
                if upload_success:
                    updated_certificates.append(timestamped_cert_name)
                    logging.info("IAM::update_ssl_certificates: "
                                 "Uploaded certificate with key '%s' to '%s': "
                                 % (cert_name, timestamped_cert_name))
                else:
                    logging.warn("IAM::update_ssl_certificates: "
                                 "Failed to upload certificate '%s' as '%s': "
                                 % (cert_name, timestamped_cert_name))
            except AWSQueryConnection.ResponseError as error:
                logging.warn("IAM::update_ssl_certificates: "
                             "Could not update certificate '%s': "
                             "Error %s - %s" % (timestamped_cert_name,
                                                error.status,
                                                error.reason))
        return updated_certificates

    def get_remote_certificate(self, cert_name, stack_name):
        """
        Check to see if the remote certificate exists already in AWS

        Args:
            cert_name(string): The name of the certificate entry to look up
            stack_name(string): The name of the stack
            ssl_data(dictionary): The configuration data for this
                certificate entry

        Returns:
            exists(bool): True if remote AWS certificate exists, false otherwise
        """

        try:
            cert_id = "{0}-{1}".format(cert_name, stack_name)
            logging.info("IAM::get_remote_certificate: "
                         "Looking for certificate '%s'.."
                         % (cert_id))

            # Fetch the remote AWS certificate configuration data
            # Fetching the response could throw an exception
            remote_cert_response = self.conn_iam.get_server_certificate(cert_id)
            remote_cert_result = remote_cert_response['get_server_certificate_response']['get_server_certificate_result']
            remote_cert_certificate = remote_cert_result["server_certificate"]

            remote_cert_data = {
                "cert": remote_cert_certificate.get("certificate_body",
                                                    None),
                "chain": remote_cert_certificate.get("certificate_chain",
                                                     None),
                "key": remote_cert_certificate.get("certificate_key",
                                                   None),
            }
            return remote_cert_data
        # Handle any problems connecting to the remote AWS
        except AWSQueryConnection.ResponseError as error:
            logging.info("IAM::get_remote_certificate: "
                         "Could not find certificate '%s': "
                         "Error %s - %s" % (cert_id,
                                            error.status,
                                            error.reason))
            return None
        except Exception as e:
            logging.info("IAM::get_remote_certificate: "
                         "Could not find certificate '%s': "
                         "Error %s - %s" % (cert_id,
                                            e.status,
                                            e.reason))
            return

    def compare_remote_certificate_data(self, cert_name, stack_name, ssl_data):
        """
        Check to see if the remote certificate exists already in AWS

        Args:
            cert_name(string): The name of the certificate entry to look up
            stack_name(string): The name of the stack
            ssl_data(dictionary): The configuration data for this
                certificate entry

        Returns:
            exists(bool): True if remote AWS certificate exists, false otherwise
        """

        try:
            cert_id = "{0}-{1}".format(cert_name, stack_name)
            logging.info("IAM::get_remote_certificate: "
                         "Looking for certificate '%s'.."
                         % (cert_id))

            # Fetch the remote AWS certificate configuration data
            # Fetching the response could throw an exception
            remote_cert_response = self.conn_iam.get_server_certificate(cert_id)
            remote_cert_result = remote_cert_response['get_server_certificate_response']['get_server_certificate_result']
            remote_cert_certificate = remote_cert_result["server_certificate"]

            remote_cert_data = {
                "cert": remote_cert_certificate.get("certificate_body",
                                                    None),
                "chain": remote_cert_certificate.get("certificate_chain",
                                                     None),
                "key": remote_cert_certificate.get("certificate_key",
                                                   None),
            }
            # Compare the local cert and chain certificates to remote
            if self.compare_certificate_data(ssl_data, remote_cert_data):
                logging.info("IAM::get_remote_certificate: "
                             "Local and remote certificates are equal, "
                             "certificate id '%s' "
                             % (cert_name))
                return True
            else:
                logging.info("IAM::get_remote_certificate: "
                             "Local and remote certificates are not the same, "
                             "certificate id '%s' "
                             % (cert_id))
                return False
        # Handle any problems connecting to the remote AWS
        except AWSQueryConnection.ResponseError as error:
                    logging.info("IAM::get_remote_certificate: "
                                 "Could not find certificate '%s': "
                                 "Error %s - %s" % (cert_id,
                                                    error.status,
                                                    error.reason))
                    return False

        return False

    def compare_certificate_data(self, cert_data1, cert_data2):
        """
        Compare two sets of certificate data for equality

        Args:
            cert1(dictionary): Dictionary of certificate data,
                with certs, chains and keys
            cert2(dictionary): Dictionary of certificate data,
                with certs, chains and keys

        Returns:
            are_equal: True if the certficate data are equal,
            false otherwise
        """

        are_equal = False
        certs_are_equal = self.compare_certs_body(cert_data1.get("cert", None),
                                                  cert_data2.get("cert", None))
        if not certs_are_equal:
            logging.info("IAM::compare_certificate_data: "
                         "Certificate body data is not equal")
        else:
            chains_are_equal = self.compare_certs_body(cert_data1.get("chain", None),
                                                       cert_data2.get("chain", None))
            if not chains_are_equal:
                logging.info("IAM::compare_certificate_data: "
                             "Certificate chain data is not equal")
            else:
                are_equal = True

        return are_equal

    def compare_certs_body(self,
                           text1,
                           text2):
        start_text = "-----BEGIN CERTIFICATE-----"
        end_text = "-----END CERTIFICATE-----"
        are_equal = False
        if (text1 and text2 and (len(text1) > 0) and (len(text2) > 0)):
            # Get the actual key data
            body1 = (text1.split(start_text))[1].split(end_text)[0]
            body2 = (text2.split(start_text))[1].split(end_text)[0]
            if body1 and body2:
                are_equal = (body1 == body2)

        return are_equal

    def upload_certificate(self, cert_name, stack_name, ssl_data, force=False):
        """
        Upload a certificate

        Args:
            cert_name(string): The name of the certificate entry to look up
            stack_name(string): The name of the stack
            ssl_data(dictionary): The configuration data for this certificate
                entry
            force(bool): True to upload even if certificate exists, false
                to not overwrite existing certificates

        Returns:
            success(bool): True if certificate is uploaded, False otherwise
        """
        cert_body = ssl_data['cert']
        private_key = ssl_data['key']
        try:
            cert_chain = ssl_data['chain']
        except KeyError:
            cert_chain = None

        cert_id = "{0}-{1}".format(cert_name, stack_name)

        try:
            if force or not self.get_remote_certificate(cert_name,
                                                        stack_name):
                self.conn_iam.upload_server_cert(cert_id, cert_body,
                                                 private_key,
                                                 cert_chain)
                logging.info("IAM::upload_certificate: "
                             "Uploading certificate '%s'.."
                             % (cert_name))
                return True
            else:
                logging.info("IAM::upload_certificate: "
                             "Certificate '%s' already exists "
                             "and not forced so skipping upload."
                             % (cert_name))
                return False
        except AWSQueryConnection.ResponseError as error:
            logging.warn("IAM::upload_certificate: "
                         "Problem uploading certificate '%s': "
                         "Error %s - %s" % (cert_name,
                                            error.status,
                                            error.reason))
            return False

        return False

    def delete_certificate(self, cert_name, stack_name, max_retries=1, retry_delay=10):
        """
        Delete a certificate from AWS, we can retry with delay, default is to only
        try once.

        Args:
                cert_name(string): The name of the certificate entry to look up
                stack_name(string): The name of the stack
                max_retries(int): The number of retries to carry out on the operation
                retry_delay(int): The retry delay of the operation

        Returns:
            success(bool): True if a certificate is deleted, False otherwise
        """
        cert_id = "{0}-{1}".format(cert_name, stack_name)
        # Try to delete cert, but handle any problems on
        # individual deletes and
        # continue to delete other certs
        retries = 0
        while retries < max_retries:
            retries += 1
            try:
                if self.get_remote_certificate(cert_name,
                                               stack_name):
                    try:
                        self.conn_iam.delete_server_cert(cert_id)
                        logging.info("IAM::delete_certificate: "
                                     "Deleting certificate '%s'.."
                                     % (cert_name))
                        return True
                    except BotoServerError as e:
                        logging.warning("IAM::delete_certificate: Cannot delete ssl cert, reason '%s', "
                                        "waiting %s seconds on retry %s/%s"
                                        % (e.error_message, retry_delay, retries, max_retries))
                        # Only sleep if we're going to try again
                        if retries < max_retries:
                            time.sleep(retry_delay)
                else:
                    logging.info("IAM::delete_certificate: "
                                 "Certificate '%s' does not exist, "
                                 "not deleting." % (cert_name))
            except AWSQueryConnection.ResponseError as error:
                logging.warn("IAM::delete_certificate: "
                             "Could not find expected certificate '%s': "
                             "Error %s - %s" % (cert_id,
                                                error.status,
                                                error.reason))
        return False

    def get_arn_for_cert(self, cert_name):
        """
        Use a certificates name to find the arn

        Args:
            cert_name (string): The name of the certification

        Returns:
            cert_arn (string): The certifications arn if found,
                None type otherwise
        """
        cert_arn = None

        try:
            cert = self.conn_iam.get_server_certificate(cert_name)
            cert_arn = cert.arn
            logging.info("IAM::get_arn_for_cert: "
                         "Found arn '%s' for certificate '%s'"
                         % (cert_arn, cert_name))
        except:
            cert_arn = None
            logging.warn("IAM::get_arn_for_cert: "
                         "Could not find arn for certificate '%s'"
                         % (cert_name))

        return cert_arn
