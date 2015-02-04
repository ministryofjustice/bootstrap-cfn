#!/usr/bin/env python

import sys
import urllib2
import json
import yaml
import time
from helpers.config import AWSConfig, ProjectConfig, ConfigParser
from awsutils.cloudformation import Cloudformation
from awsutils.ec2 import EC2

import os

from fabric.api import env, task, sudo, execute, run, parallel, settings
from fabric.contrib.project import rsync_project, upload_project
from fabric.operations import put

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
def user(x):
    env.user = x

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
    #stack_name = "%s-%s-%s" % (env.application, env.environment, time.strftime('%Y%m%d-%H%M', time.gmtime()))
    stack_name = "%s-%s" % (env.application, env.environment)
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

def get_stack_instances_ips(stack_name):
    if env.aws is None:
        print "\n[ERROR] Please specify an AWS account, e.g 'aws:dev'"
        sys.exit(1)

    aws_config = AWSConfig(env.aws)
    cfn = Cloudformation(aws_config)
    ec2 = EC2(aws_config)
    instance_id_list = cfn.get_stack_instance_ids(stack_name)
    return ec2.get_instance_public_ips(instance_id_list)

@task
def get_stack_addresses():
    if env.environment is None:
        print "\n[ERROR] Please specify an environment, e.g 'environment:dev'"
        sys.exit(1)
    if env.application is None:
        print "\n[ERROR] Please specify an application, e.g 'application:peoplefinder'"
        sys.exit(1)
    stack_name = "%s-%s" % (env.application, env.environment)
    res = get_stack_instances_ips(stack_name)
    print res
    return res

@task
def rsync():
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
        # check if there is a deploy repo in a predefined location
        app_yaml = '../{0}-deploy/{0}.yaml'.format(env.application)
        if os.path.exists(app_yaml):
            env.config = app_yaml
        else:
            print "\n[ERROR] Please specify a config file, e.g 'config:/tmp/sample-application.yaml'"
            sys.exit(1)
           
    work_dir = os.path.join('..', '{0}-deploy'.format(env.application))
    # LOAD AWS CONFIG FROM ~/.config.yaml
    aws_config = AWSConfig(env.aws)

    project_config = ProjectConfig(env.config, env.environment)
    cfg = project_config.config
    
    local_state_dir = os.path.join(work_dir, 'vendor', '_root', '.')
    local_formula_dir= os.path.join(work_dir, 'vendor', 'formula-repos', '.')
    local_pillar_dir = os.path.join(work_dir, 'pillar', '.')
    local_salt_dir = os.path.join(work_dir, 'salt', '.')

    remote_state_dir = cfg['salt'].get('remote_state_dir', '/srv/salt')
    remote_pillar_dir = cfg['salt'].get('remote_pillar_dir', '/srv/pillar')
    remote_formula_dir = cfg['salt'].get('remote_formula_dir', '/srv/formula-repos')

    #if not os.path.exists(local_state_dir):
    #    shake(work_dir)

    ips = get_stack_addresses()
    for ip in ips:
        env.host_string = '{0}@{1}'.format(env.user, ip)
        sudo('mkdir -p {0}'.format(remote_state_dir))
        sudo('mkdir -p {0}'.format(remote_pillar_dir))
        sudo('mkdir -p {0}'.format(remote_formula_dir))
        upload_project(remote_dir=remote_formula_dir, local_dir=local_formula_dir, use_sudo=True)
        upload_project(remote_dir=remote_state_dir, local_dir=local_state_dir, use_sudo=True)
        upload_project(remote_dir=remote_state_dir, local_dir=local_salt_dir, use_sudo=True)
        upload_project(remote_dir=remote_pillar_dir, local_dir=os.path.join(local_pillar_dir, env.environment, '.'), use_sudo=True)

