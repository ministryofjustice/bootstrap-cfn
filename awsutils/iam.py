import boto.iam

class IAM:

    conn_cfn = None
    config = None

    def __init__(self, config):
        self.config = config
        if self.config.aws_access is not None and self.config.aws_secret is not None:
            self.conn_iam = boto.iam.connect_to_region(
                region_name=self.config.aws_region,
                aws_access_key_id=self.config.aws_access,
                aws_secret_access_key=self.config.aws_secret)
        else:
            print "[ERROR] No AWS credentials"
            sys.exit(1)

    def upload_ssl_certificate(self, ssl_config):
        for cert_name, ssl_data in ssl_config.items():
            cert_body = ssl_data['cert']
            private_key = ssl_data['key']
            try:
                cert_chain = ssl_data['chain']
            except:
                cert_chain = None
            self.conn_iam.upload_server_cert(cert_name, cert_body, private_key, cert_chain)
        return True

    def delete_ssl_certifacte(self, ssl_config):
        for cert_name in ssl_config.keys():
            self.conn_iam.delete_server_cert(cert_name)
        return True
