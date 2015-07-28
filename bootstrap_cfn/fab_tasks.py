#!/usr/bin/env python

import logging
import os
import sys
import time
import uuid

from boto.route53.exception import DNSServerError

from fabric.api import env, task
from fabric.colors import green, red
from fabric.utils import abort

from bootstrap_cfn.cloudformation import Cloudformation
from bootstrap_cfn.config import ConfigParser, ProjectConfig
from bootstrap_cfn.elb import ELB
from bootstrap_cfn.iam import IAM
from bootstrap_cfn.r53 import R53
from bootstrap_cfn.utils import tail


# Default fab config. Set via the tasks below or --set
env.setdefault('application')
env.setdefault('environment')
env.setdefault('aws')
env.setdefault('config')
env.setdefault('stack_passwords')
env.setdefault('blocking', True)
env.setdefault('aws_region', 'eu-west-1')

# GLOBAL VARIABLES
TIMEOUT = 3600
RETRY_INTERVAL = 10

# This is needed because pkgutil wont pick up modules
# imported in a fabfile.
path = env.real_fabfile or os.getcwd()
sys.path.append(os.path.dirname(path))


@task
def aws(profile_name):
    """
    Set the AWS account to use

    Sets the environment variable 'aws' to the name of the
    account to use in the AWS config file (~/.aws/credentials.yaml)

    Args:
        profile_name(string): The string to set the environment
        variable to
    """
    env.aws = str(profile_name).lower()


@task
def environment(environment_name):
    """
    Set the environment section to be read from the project config
    file

    Sets the environment variable 'environment'.
    The named section will be read from the project's YAML file

    Args:
        environment_name(string): The string to set the
        variable to
    """
    env.environment = str(environment_name).lower()


@task
def application(application_name):
    """
    Set the application name

    Sets the environment variable 'application' to
    an application name. Which is just a name to
    associate with Cloudformation stack

    Args:
        application_name(string): The string to set the
        variable to
    """
    env.application = str(application_name).lower()


@task
def tag(tag):
    """
    Set a tag for the stack

    Sets the environment variable 'tag'
    This gets used to store a DNS entry to identify
    multiple stacks with the same name.
    e.g. you can tag a stack as active, or inactive,
    green or blue etc.

    Args:
        tag(string): The string to set the
        variable to
    """
    env.tag = str(tag).lower()


@task
def config(config_file):
    """
    Set the location of the project's YAML file

    Sets the environment variable 'config' to be
    the location of the project's YAML config
    file

    Args:
        config_file(string): The string to set the
        variable to
    """
    env.config = str(config_file).lower()


@task
def passwords(passwords_file):
    """
    Set the path to the project's password YAML config file

    Set the environment variable 'stack_passwords' to the
    path of the project's password file. This will be used
    to load in a dictionary of passwords to use with the
    project's components

    Args:
        passwords_file(string): The string to set the
        variable to
    """
    env.stack_passwords = str(passwords_file).lower()


@task
def blocking(block):
    """
    Set to block while waiting for stack creation or deletion to complete

    Sets the environment variable 'blocking' to True to wait on stack
    creation or deletion to complete before returning from the script.
    If false the cloudformation task will be started and the script
    will immediately exit

    Args:
        block(string): The string to set the
        variable to. Must be one of yes, true,
        t or 1
    """
    env.blocking = str(block).lower() in ("yes", "true", "t", "1")


@task
def user(username):
    """
    Sets the username to use for ssh to created instances

    Sets the environment variable 'user' to the ssh username
    to use when trying to connect to a remote instance

    Args:
        username(string): The string to set the
        variable to.
    """
    env.user = username


@task
def swap_tags(tag1, tag2):
    """
    Swap two tagged stacks.

    i.e. update the DNS text record which defines the
    random suffix associated with a stack tag.
    """
    cfn_config = get_config()
    r53_conn = get_connection(R53)
    zone_name = cfn_config.data['master_zone']
    zone_id = r53_conn.get_hosted_zone_id(zone_name)
    legacy_name = "{0}-{1}".format(env.application, env.environment)
    record1 = "stack.{0}.{1}".format(tag1, legacy_name)
    record2 = "stack.{0}.{1}".format(tag2, legacy_name)
    stack_suffix1 = r53_conn.get_record(zone_name, zone_id, record1, 'TXT')
    stack_suffix2 = r53_conn.get_record(zone_name, zone_id, record2, 'TXT')
    fqdn1 = "{0}.{1}".format(record1, zone_name)
    fqdn2 = "{0}.{1}".format(record2, zone_name)
    r53_conn.update_dns_record(zone_id, fqdn1, 'TXT', '"{0}"'.format(stack_suffix2))
    r53_conn.update_dns_record(zone_id, fqdn2, 'TXT', '"{0}"'.format(stack_suffix1))


def get_stack_name(new=False):
    """
    Get the name of the stack

    The name of the stack is a combination
    of the application and environment names
    and a randomly generated suffix.

    The env.tag dictates which randomly generated suffix
    the default env.tag is 'active'

    If new=True we generate a new stack_name and create the
    dns records to retreive it in the future.

    """
    if hasattr(env, 'tag'):
        tag = env.tag
    else:
        tag = 'active'
        env.tag = tag
    if not hasattr(env, 'stack_name') or new:
        legacy_name = "{0}-{1}".format(env.application, env.environment)
        # get_config needs a stack_name so this is a hack because we don't
        # know it yet...
        env.stack_name = 'temp'
        cfn_config = get_config()
        try:
            r53_conn = get_connection(R53)
            zone_name = cfn_config.data['master_zone']
            zone_id = r53_conn.get_hosted_zone_id(zone_name)
            record_name = "stack.{0}.{1}".format(tag, legacy_name)
            if new:
                stack_suffix = uuid.uuid4().__str__()[-8:]
                record = "{0}.{1}".format(record_name, zone_name)
                r53_conn.update_dns_record(zone_id, record, 'TXT', '"{0}"'.format(stack_suffix))
            else:
                stack_suffix = r53_conn.get_record(zone_name, zone_id, record_name, 'TXT')
            if stack_suffix:
                env.stack_name = "{0}-{1}".format(legacy_name, stack_suffix)
            else:
                env.stack_name = legacy_name
        except KeyError:
            logging.warn("No master_zone in yaml, unable to create/find DNS records for "
                         "stack name, will fallback to legacy stack names: "
                         "application-environment")
            env.stack_name = legacy_name
        except DNSServerError:
            logging.warn("Couldn't find/create DNS entry for stack suffix, "
                         "stack name, will fallback to legacy stack names: "
                         "application-environment")
            env.stack_name = legacy_name
    return env.stack_name


def _validate_fabric_env():
    if env.aws is None:
        sys.exit("\n[ERROR] Please specify an AWS account, e.g 'aws:dev'")
    if env.environment is None:
        sys.exit("\n[ERROR] Please specify an environment, e.g 'environment:dev'")
    if env.application is None:
        sys.exit("\n[ERROR] Please specify an application, e.g 'application:peoplefinder'")
    if env.config is None:
        sys.exit("\n[ERROR] Please specify a config file, e.g 'config:/tmp/sample-application.yaml'")
    elif not os.path.isfile(env.config):
        sys.exit("\n[ERROR] Config file %s does not exist" % str(env.config))

    if env.stack_passwords is not None and not os.path.exists(env.stack_passwords):
        print >> sys.stderr, "\n[ERROR] Passwords file '{0}' doesn't exist!".format(env.stack_passwords)
        sys.exit(1)


def get_config():
    _validate_fabric_env()
    project_config = ProjectConfig(
        env.config,
        env.environment,
        passwords=env.stack_passwords)

    Parser = env.get('cloudformation_parser', ConfigParser)
    cfn_config = Parser(project_config.config, get_stack_name(), environment=env.environment, application=env.application)
    return cfn_config


def get_connection(klass):
    _validate_fabric_env()
    return klass(env.aws, env.aws_region)


@task
def cfn_delete(force=False):
    """
    Delete the AWS Cloudformation stack

    Deletes the stack and the associated SSL certificates

    Args:
        force(bool): True to destroy the stack without any further
            input, False to require confirmation before deletion
    """
    if not force:
        x = raw_input("Are you really sure you want to blow away the whole stack!? (y/n)\n")
        if x not in ['y', 'Y', 'Yes', 'yes']:
            sys.exit(1)
    stack_name = get_stack_name()
    cfn_config = get_config()
    cfn = get_connection(Cloudformation)
    cfn.delete(stack_name)
    print green("\nSTACK {0} DELETING...\n").format(stack_name)

    if not env.blocking:
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
def cfn_create(test=False):
    """
    Create the AWS cloudformation stack.

    Using the configuration files, a full cloudformation
    specification will be generated and used to create a
    stack on AWS.
    """
    stack_name = get_stack_name(new=True)
    cfn_config = get_config()

    cfn = get_connection(Cloudformation)
    if test:
        print cfn_config.process()
        return
    # Upload any SSL certs that we may need for the stack.
    if 'ssl' in cfn_config.data:
        print green("Uploading SSL certificates to stack")
        iam = get_connection(IAM)
        iam.upload_ssl_certificate(cfn_config.ssl(), stack_name)
    # Useful for debug
    # print cfn_config.process()
    # Inject security groups in stack template and create stacks.
    try:
        stack = cfn.create(stack_name, cfn_config.process(), tags=get_cloudformation_tags())
    except:
        # cleanup ssl certificates if any
        if 'ssl' in cfn_config.data:
            print red("Deleting SSL certificates from stack")
            iam.delete_ssl_certificate(cfn_config.ssl(), stack_name)
        import traceback
        abort(red("Failed to create: {error}".format(error=traceback.format_exc())))

    print green("\nSTACK {0} CREATING...\n").format(stack_name)

    if not env.blocking:
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


@task
def update_certs():
    """
    Update the ssl certificates

    This will read in the certificates from the config
    file, update them in AWS Iam, and then also handle
    setting the certificates on ELB's
    """

    stack_name = get_stack_name()
    cfn_config = get_config()
    # Upload any SSL certificates to our EC2 instances
    updated_count = False
    if 'ssl' in cfn_config.data:
        logging.info("Reloading SSL certificates...")
        iam = get_connection(IAM)
        updated_count = iam.update_ssl_certificates(cfn_config.ssl(),
                                                    stack_name)
    else:
        logging.error("No ssl section found in cloud config file, aborting...")
        sys.exit(1)

    # Arbitrary wait to allow SSL upload to register with AWS
    # Otherwise, we can get an ARN for the load balancer certificates
    # without it being ready to assign
    time.sleep(3)

    # Set the certificates on ELB's if we have any
    if updated_count > 0:
        if 'elb' in cfn_config.data:
            logging.info("Setting load balancer certificates...")
            elb = get_connection(ELB)
            elb.set_ssl_certificates(cfn_config.ssl(), stack_name)
    else:
        logging.error("No certificates updated so skipping "
                      "ELB certificate update...")


def get_cloudformation_tags():
    """
    Get a top-level set of tags for the stack, these will propagate
    down so that many of the created resources will be tagged in
    addition. Notable omissions are EBS volumes and route53 resources
    """
    return {
        "Env": env.environment,
    }


@task
def display_elb_dns_entries():
    """
    Prints out the ELB name(s) and the corresponding DNS name(s) for every ELB
    in the environment provided.
    """
    stack_name = get_stack_name()
    elb = get_connection(ELB)
    elb_dns_list = elb.list_domain_names(stack_name)
    for elb_dns in elb_dns_list:
        print "\n\nELB name: {0}        DNS: {1}".format(elb_dns['elb_name'], elb_dns['dns_name'])
