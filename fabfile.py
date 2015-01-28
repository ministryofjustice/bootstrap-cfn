#!/usr/bin/env python

import sys
import time
from fabric.api import env, task
from awsutils.cloudformation import Cloudformation
from helpers.config import AWSConfig, ProjectConfig, ConfigParser



### GLOBAL VARIABLES
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

    # LOAD AWS CONFIG FROM ~/.config.yaml
    aws_config = AWSConfig(env.aws)

    # LOAD PROJECT CONFIG YAML FILE AND TRANSFORM TO CLOUDFORMATION FORMAT
    project_config = ProjectConfig(env.config, env.environment)
    cfn_config = ConfigParser(project_config.config)

    # CREATE CLOUDFORMATION STACK
    cfn = Cloudformation(aws_config)
    stack_name = "%s-%s-%s" % (env.application, env.environment, time.strftime('%Y%m%d-%H%M', time.gmtime()))
    cfn.create(stack_name, cfn_config.process())
