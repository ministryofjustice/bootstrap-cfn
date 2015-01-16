#!/usr/bin/env python

import sys
import urllib2
import json
import yaml
from fabric.api import env, task, sudo, execute, run, parallel, settings
from awsutils.cloudformation import Cloudformation
from helpers.config import AWSConfig, ProjectConfig


### GLOBAL VARIABLES
env.base_stack_url = 'https://raw.githubusercontent.com/ministryofjustice/bootstrap-cfn/master/base-cfn.json'
env.application = None
env.environment = None
env.aws = None
env.config = None
TIMEOUT = 3600 
RETRY_INTERVAL = 10

@task
def aws(x):
    env.aws = str(x).lower()

@task
def environment(x):
    env.environment = str(x).lower()

@task
def application(x):
    env.application = str(x).lower()

@task
def config(x):
    env.config = str(x).lower()

@task
def cfn_create():
    if env.aws is None:
        print "\n[ERROR] Please specify an AWS account, e.g 'aws:dev'"
        sys.exit(1)
    if env.environment is None:
        print "\n[ERROR] Please specify an environment, e.g 'environment:dev'"
        sys.exit(1)
    if env.application is None:
        print "\n[ERROR] Please specify an application, e.g 'application:peoplefinder'"
        sys.exit(1)
    if env.config is None:
        print "\n[ERROR] Please specify a config file, e.g 'config:/tmp/sample-application.yaml'"
        sys.exit(1)

    # DOWNLOAD BaseHost CFN STACK
    base_stack = json.loads(urllib2.urlopen(env.base_stack_url).read())
    print base_stack
    print

    aws_config = AWSConfig(env.aws)
    project = ProjectConfig(env.config, env.environment)
    print project.config

    # ADD SECURITY GROUPS
    if 'ec2' in project.config:
        for server in project.config['ec2'].keys():
            if 'security_groups' in project.config['ec2'][server]:
                if 'ingress' in project.config['ec2'][server]['security_groups']:
                    for port in project.config['ec2'][server]['security_groups']['ingress'].keys():
                        print port
                        print project.config['ec2'][server]['security_groups']['ingress'][port]




# "SecurityGroupIngress" : [
#           {"IpProtocol" : "tcp", "FromPort" : "80", "ToPort" : "80", "CidrIp" : "0.0.0.0/0"},
#           {"IpProtocol" : "tcp", "FromPort" : "22", "ToPort" : "22", "CidrIp" : "0.0.0.0/0"}
#         ]
