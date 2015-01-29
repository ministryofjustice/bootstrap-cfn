#!/usr/bin/env python

import sys
import urllib2
import json
import yaml
import time
from fabric.api import env, task, sudo, execute, run, parallel, settings
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
def blocking(x):
    env.blocking = str(x).lower()

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
    cfg = project_config.config
    cfn_config = ConfigParser(cfg)
    # DOWNLOAD BaseHost CFN STACK
    cfn = Cloudformation(aws_config)

    # Inject security groups in stack template and create stacks.
    stack_name = "%s-%s-%s" % (env.application, env.environment, time.strftime('%Y%m%d-%H%M', time.gmtime()))
    stack = cfn.create(stack_name, cfn_config.process())

    if  hasattr(env, 'blocking') and env.blocking.lower() == 'false':
        print stacks
        print 'Running in non blocking mode. Exiting.'
        sys.exit(0) 

    # Wait for stacks to complete
    print 'Waiting for stack to complete.'
    attempts = 0
    while True:
        if cfn.stack_done(stack):
            break
        if attempts == TIMEOUT/RETRY_INTERVAL:
            print '[ERROR] Stack creation timed out'
            sys.exit(1)
        attempts += 1
        time.sleep(RETRY_INTERVAL)

    print 'Stacks completed, checking results.'
    stack_evt = cfn.get_last_stack_event(stack)
    print '{0}: {1}'.format(stack_evt.stack_name, stack_evt.resource_status)
    if stack_evt.resource_status == 'CREATE_COMPLETE':
        print 'Successfully built stack {0}.'.format(stack)
    else:
        print 'Failed to create stack: {0}'.format(stack)

