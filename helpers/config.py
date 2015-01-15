import sys
import os
import yaml


class AWSConfig:

    aws_access = None
    aws_secret = None
    aws_region = 'eu-west-1'

    def __init__(self, account, fp=False):
        f = None
        if fp is True:
            if os.path.exists(fp):
                f = open(fp).read()
            else:
                print "File does not exist"
                sys.exit(1)
        else:
            f = open(os.path.expanduser("~") + "/.config.yaml").read()

        if f:
            d = yaml.load(f)['provider_zones']
            self.aws_access = d[account]['aws_access_key_id']
            self.aws_secret = d[account]['aws_secret_access_key']


class ProjectConfig:

    config = None

    def __init__(self, config, environment):
        if os.path.exists(config):
            f = yaml.load(open(config).read())
            self.config = f[environment]
