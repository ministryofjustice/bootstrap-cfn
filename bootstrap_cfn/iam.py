import boto.iam
from boto.exception import NoAuthHandlerFound
from boto.provider import ProfileNotFoundError

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
            cert_body = ssl_data['cert']
            private_key = ssl_data['key']
            try:
                cert_chain = ssl_data['chain']
            except:
                cert_chain = None
            cert_id = "{0}-{1}".format(cert_name, stack_name)
            self.conn_iam.upload_server_cert(cert_id, cert_body, private_key, cert_chain)
        return True

    def delete_ssl_certificate(self, ssl_config, stack_name):
        for cert_name in ssl_config.keys():
            cert_id = "{0}-{1}".format(cert_name, stack_name)
            self.conn_iam.delete_server_cert(cert_id)
        return True
