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


def modify_sg(stack_data, sg_data):
    groups = []
    for sg in sg_data:
        sg_struct = {
                'Type': 'AWS::EC2::SecurityGroup',
                'Properties': {
                    'GroupDescription': 'Auto generated SG',
                    'SecurityGroupIngress': sg_data[sg]['rules']
                }
            }
        stack_data['Resources'][sg] = sg_struct
    return stack_data

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
    aws_config = AWSConfig(env.aws)
    project_config = ProjectConfig(env.config, env.environment)
    cfg = project_config.config

    stacks = []
    for env in cfg[app]:
        for host, data in cfg[env][EC2_KEY].items():
            stack_data = modify_sg(base_stack, data['security_groups'])
            print stack_data
            stacks.append(create_stack(host, stack_data))

    print 'Waiting for stacks to complete.'
    attempts = 0
    while True:
        if all([stack_done(x) for x in stacks]):
            break
        if attempts == TIMEOUT/RETRY_INTERVAL:
            print '[ERROR] Stack creation timed out'
            sys.exit(1)
        attempts += 1
        time.sleep(RETRY_INTERVAL)

    print 'All stacks completed.'    

