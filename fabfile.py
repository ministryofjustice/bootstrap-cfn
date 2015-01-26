#!/usr/bin/env python

import sys
import urllib2
import json
import yaml
import time
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

    # DOWNLOAD BaseHost CFN STACK
    base_stack = json.loads(urllib2.urlopen(env.base_stack_url).read())
    aws_config = AWSConfig(env.aws)
    project_config = ProjectConfig(env.config, env.environment)
    cfg = project_config.config
    cfn = Cloudformation(aws_config)

    # Inject security groups in stack template and create stacks.
    stacks = []
    for host, data in cfg['ec2'].items():
        stack_data = cfn.modify_sg(base_stack, data['security_groups'])
        stack_name  = '{0}-{1}'.format(host, str(int(time.time())))
        params = data['parameters'].items() if 'parameters' in data else []
        stacks.append(cfn.create(stack_name, json.dumps(stack_data), parameters=params))

    if  hasattr(env, 'blocking') and env.blocking.lower() == 'false':
        print stacks
        print 'Running in non blocking mode. Exiting.'
        sys.exit(0) 

    # Wait for stacks to complete
    print 'Waiting for stacks to complete.'
    attempts = 0
    while True:
        if all([cfn.stack_done(x) for x in stacks]):
            break
        if attempts == TIMEOUT/RETRY_INTERVAL:
            print '[ERROR] Stack creation timed out'
            sys.exit(1)
        attempts += 1
        time.sleep(RETRY_INTERVAL)

    print 'All stacks completed, checking results.'
    success_cnt = 0
    for stack in stacks:
        stack_evt = cfn.get_last_stack_event(stack)
        print '{0}: {1}'.format(stack_evt.stack_name,
                stack_evt.resource_status)
        if stack_evt.resource_status == 'CREATE_COMPLETE':
            success_cnt +=1
    print 'Successfully built {0} out of {0} stacks.'.format(success_cnt,
            len(stacks))

