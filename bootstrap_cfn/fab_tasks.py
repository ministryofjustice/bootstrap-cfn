#!/usr/bin/env python

import os
import sys

from fabric.api import env, task
from fabric.utils import abort
from fabric.colors import green, red

from bootstrap_cfn.config import ProjectConfig, ConfigParser
from bootstrap_cfn.cloudformation import Cloudformation
from bootstrap_cfn.iam import IAM
from bootstrap_cfn.utils import tail


# GLOBAL VARIABLES
env.application = None
env.environment = None
env.aws = None
env.config = None
env.password = None
TIMEOUT = 3600
RETRY_INTERVAL = 10

# This is needed because pkgutil wont pick up modules
# imported in a fabfile.
path = env.real_fabfile or os.getcwd()
sys.path.append(os.path.dirname(path))


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
def passwords(x):
    env.stack_passwords = str(x).lower()


@task
def blocking(x):
    env.blocking = str(x).lower()


@task
def user(x):
    env.user = x


def get_stack_name():
    if hasattr(env, 'stack_name'):
        return env.stack_name
    return "%s-%s" % (env.application, env.environment)


def _validate_fabric_env():
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

    if hasattr(env, 'stack_passwords') and env.stack_passwords is not None:
        if not os.path.exists(env.stack_passwords):
            print >> sys.stderr, "\n[ERROR] Passwords file '{0}' doesn't exist!".format(env.stack_passwords)
            sys.exit(1)
    else:
        env.stack_passwords = None

    if not hasattr(env, 'aws_region'):
        env.aws_region = 'eu-west-1'


def get_config():
    _validate_fabric_env()
    project_config = ProjectConfig(
        env.config,
        env.environment,
        passwords=env.stack_passwords)

    cfn_config = ConfigParser(project_config.config, get_stack_name())
    return cfn_config

def get_connection(klass):
    _validate_fabric_env()
    return klass(env.aws, env.aws_region)


@task
def cfn_delete(force=False):
    if not force:
        x = raw_input("Are you really sure you want to blow away the whole stack!? (y/n)\n")
        if x not in ['y', 'Y', 'Yes', 'yes']:
            sys.exit(1)
    stack_name = get_stack_name()
    cfn_config = get_config()
    cfn = get_connection(Cloudformation)
    cfn.delete(stack_name)
    print green("\nSTACK {0} DELETING...\n").format(stack_name)

    if hasattr(env, 'blocking') and env.blocking.lower() == 'false':
        print 'Running in non blocking mode. Exiting.'
        sys.exit(0)

    # Wait for stacks to delete
    print 'Waiting for stack to delete.'

    tail(cfn, stack_name)

    if cfn.stack_missing(stack_name):
        print green("Stack successfully deleted")
    else:
        print red("Stack deletion was unsuccessfull")

    if 'ssl' in cfn_config.data:
        iam = get_connection(IAM)
        iam.delete_ssl_certificate(cfn_config.ssl(), stack_name)


@task
def cfn_create():
    stack_name = get_stack_name()
    cfn_config = get_config()

    cfn = get_connection(Cloudformation)
    # Upload any SSL certs that we may need for the stack.
    if 'ssl' in cfn_config.data:
        iam = get_connection(IAM)
        iam.upload_ssl_certificate(cfn_config.ssl(), stack_name)
    # Useful for debug
    #print cfn_config.process()
    # Inject security groups in stack template and create stacks.
    try:
        stack = cfn.create(stack_name, cfn_config.process())
    except Exception as e:
        abort(red("Failed to create: {error}".format(error=e.message)))

    print green("\nSTACK {0} CREATING...\n").format(stack_name)

    if hasattr(env, 'blocking') and env.blocking.lower() == 'false':
        print 'Running in non blocking mode. Exiting.'
        sys.exit(0)

    tail(cfn, stack_name)
    stack_evt = cfn.get_last_stack_event(stack)

    if stack_evt.resource_status == 'CREATE_COMPLETE':
        print 'Successfully built stack {0}.'.format(stack)
    else:
        # So delete the SSL cert that we uploaded
        if 'ssl' in cfn_config.data:
            iam.delete_ssl_certificate(cfn_config.ssl(), stack_name)
        abort('Failed to create stack: {0}'.format(stack))
