#!/usr/bin/env python

import logging
import os
import sys
import time
import uuid

import boto3

import dns.resolver

from fabric.api import env, task
from fabric.colors import green, red
from fabric.utils import abort

from bootstrap_cfn.autoscale import Autoscale
from bootstrap_cfn.cloudformation import Cloudformation
from bootstrap_cfn.config import ConfigParser, ProjectConfig
from bootstrap_cfn.elb import ELB
from bootstrap_cfn.errors import BootstrapCfnError, CfnConfigError, CloudResourceNotFoundError, DNSRecordNotFoundError, ZoneIDNotFoundError
from bootstrap_cfn.iam import IAM
from bootstrap_cfn.r53 import R53
from bootstrap_cfn.utils import tail
from bootstrap_cfn.vpc import VPC


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

# Set up the logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bootstrap-cfn")
logging.getLogger("requests").setLevel(logging.WARNING)


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
    # Setup boto so we actually use this environment
    boto3.setup_default_session(profile_name=env.aws)


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


def apply_maintenance_criteria(elb):
    '''
    Applies maintenance criteria to elb

    Returns True if the maintenance should continue
    '''
    return elb['scheme'] == 'internet-facing'


@task
def enter_maintenance(maintenance_ip):
    '''
    Puts stack into maintenance mode

    Sets all internet facing elb hostnames to resolve to given maintenance_ip
    '''
    cfn_config = get_config()
    r53_conn = get_connection(R53)

    cached_zone_ids = {}
    for elb in cfn_config.data['elb']:
        if not apply_maintenance_criteria(elb):
            continue

        record = "{name}.{hosted_zone}".format(**elb)
        zone_id = get_cached_zone_id(r53_conn, cached_zone_ids, elb['hosted_zone'])
        print green("Attempting to update: \"{0}\":\"{1}\"".format(record, maintenance_ip))
        r53_conn.update_dns_record(zone_id, record, 'A', maintenance_ip)


@task
def exit_maintenance():
    """
    Exit maintenance mode

    Sets internet-facing elbs hostnames
    back to the ELB DNS alias
    """
    r53_conn = get_connection(R53)
    elb_conn = get_connection(ELB)

    cfn_config = get_config()
    stack_name = get_stack_name()

    # In order to traverse from config yaml all the way to the DNS alias for the ELB
    # it is required to construct a logical to physical naming for the elbs. So first
    # get all elbs for this stack from AWS cloudformation, to be used as a
    # filter on the next step
    # Note: if stack does not exist this will throw a BotoServerError
    stack_elbs = dict([
        (x.logical_resource_id, x.physical_resource_id)
        for x in elb_conn.cfn.get_stack_load_balancers(stack_name)])

    # filter stack related load balancers (as opposed to all stack elbs in the account)
    full_load_balancers = elb_conn.conn_elb.get_all_load_balancers(
        load_balancer_names=stack_elbs.values())

    cached_zone_ids = {}
    # loop through elb config entries and change internet facing ones
    for elb in cfn_config.data['elb']:
        if not apply_maintenance_criteria(elb):
            continue
        record = "{name}.{hosted_zone}".format(**elb)
        # obtain physical name from dict lookup, by converting elb name into safe name
        # into logical name
        phys_name = stack_elbs[mold_to_safe_elb_name(elb['name'])]

        dns_name = [x.dns_name for x in full_load_balancers if x.name == phys_name]
        if len(dns_name) == 1:
            dns_name = dns_name[0]
        else:
            raise BootstrapCfnError(
                "Lookup for elb with physical name \"{0}\" returned {1} load balancers, "
                "while only exactly 1 was expected".format(phys_name, len(dns_name)))
        zone_id = get_cached_zone_id(r53_conn, cached_zone_ids, elb['hosted_zone'])

        # For record_value provide list of params as needed by function set_alias
        # http://boto.readthedocs.org/en/latest/ref/route53.html#boto.route53.record.Record.set_alias
        record_value = [
            # alias_hosted_zone_id
            R53.AWS_ELB_ZONE_ID[env.aws_region],
            # alias_dns_name
            dns_name,
            # alias_evaluate_target_health (True/False)
            False
        ]
        print green("Attempting to update: \"{0}\":{1}".format(record, record_value))
        r53_conn.update_dns_record(zone_id, record, 'A', record_value, is_alias=True)


def get_cached_zone_id(r53_conn, zone_dict, zone_name):
    '''
    Gets and cache zone id from route53

    If we are looping through ELBs we may just have different hostnames in same zone,
    so feel free to cache it (and drink a shot because I said 'cache')

    raises CloudResourceNotFoundError if zone is not found
    '''
    if zone_name not in zone_dict:
        # not found, look it up, cache it up ..
        lookup_zone = r53_conn.get_hosted_zone_id(zone_name)
        if not lookup_zone:
            raise CloudResourceNotFoundError("Zone ID not found for zone: {}".format(zone_name))
        zone_dict[zone_name] = lookup_zone
    return zone_dict[zone_name]


def mold_to_safe_elb_name(elb_name):
    '''
    Molds the elb_name to match cloudformation naming of ELBs
    '''
    return 'ELB' + elb_name.replace('-', '').replace('.', '').replace('_', '')


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
    if new:
        # For back-compatibility
        set_stack_name()

    if hasattr(env, 'tag'):
        stack_tag = env.tag
    else:
        stack_tag = 'active'
        env.tag = stack_tag
    if not hasattr(env, 'stack_name'):
        legacy_name = "{0}-{1}".format(env.application, env.environment)
        # get_config needs a stack_name so this is a hack because we don't
        # know it yet...
        env.stack_name = 'temp'
        zone_name = get_basic_config().get('master_zone', None)
        if not zone_name:
            raise CfnConfigError("No master_zone in yaml, unable to create/find DNS records for stack name")
        logger.info("fab_tasks::get_stack_name: Found master zone '{}' in config...".format(zone_name))

        record_name = "stack.{0}.{1}".format(stack_tag, legacy_name)
        dns_name = "{}.{}".format(record_name, zone_name)
        try:
            stack_suffix = dns.resolver.query(dns_name, 'TXT')[0].to_text().replace('"', "")
            logger.info("fab_tasks::get_stack_name: Found stack suffix '{}' "
                        "for dns record '{}'... ".format(stack_suffix, dns_name))
            env.stack_name = "{0}-{1}".format(legacy_name, stack_suffix)
            logger.info("fab_tasks::get_stack_name: Found stack name '{}'...".format(env.stack_name))
        except dns.resolver.NXDOMAIN:
            raise DNSRecordNotFoundError(zone_name)

    return env.stack_name


def set_stack_name():
    """
    Set the name of the stack

    The name of the stack is a combination
    of the application and environment names
    and a randomly generated suffix.

    The env.tag dictates which randomly generated suffix
    the default env.tag is 'active'

    We generate a new stack_name and create the
    dns records to retreive it in the future.

    """
    if hasattr(env, 'tag'):
        stack_tag = env.tag
    else:
        stack_tag = 'active'
        env.tag = stack_tag
    legacy_name = "{0}-{1}".format(env.application, env.environment)
    # get_config needs a stack_name so this is a hack because we don't
    # know it yet...
    env.stack_name = 'temp'
    cfn_config = get_config()
    r53_conn = get_connection(R53)
    zone_name = cfn_config.data.get('master_zone', None)
    if not zone_name:
        raise CfnConfigError("No master_zone in yaml, unable to create/find DNS records for stack name")
    logger.info("fab_tasks::set_stack_name: Found master zone '{}' in config...".format(zone_name))

    zone_id = r53_conn.get_hosted_zone_id(zone_name)
    if not zone_id:
        raise ZoneIDNotFoundError(zone_name)
    logger.info("fab_tasks::set_stack_name: Found zone id '{}' "
                "for zone name '{}'...".format(zone_id, zone_name))
    record_name = "stack.{0}.{1}".format(stack_tag, legacy_name)

    stack_suffix = uuid.uuid4().__str__()[-8:]
    record = "{0}.{1}".format(record_name, zone_name)
    logger.info("fab_tasks::set_stack_name: "
                "Creating stack suffix {} "
                "for record '{}' "
                "in zone id '{}'...".format(stack_suffix, record, zone_id))
    # Let DNS update DNSServerError propogate
    r53_conn.update_dns_record(zone_id, record, 'TXT', '"{0}"'.format(stack_suffix))
    env.stack_name = "{0}-{1}".format(legacy_name, stack_suffix)
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


def get_basic_config():
    """
    Returns the basic unparsed configuration file for the project
    """
    _validate_fabric_env()
    project_config = ProjectConfig(
        env.config,
        env.environment,
        passwords=env.stack_passwords)
    return project_config.config


def get_config():
    Parser = env.get('cloudformation_parser', ConfigParser)
    cfn_config = Parser(get_basic_config(), get_stack_name(), environment=env.environment, application=env.application)
    return cfn_config


def get_connection(klass):
    _validate_fabric_env()
    return klass(env.aws, env.aws_region)


@task
def cfn_delete(force=False, pre_delete_callbacks=None):
    """
    Delete the AWS Cloudformation stack

    Deletes the stack and the associated SSL certificates

    Args:
        force(bool): True to destroy the stack without any further
            input, False to require confirmation before deletion
        pre_delete_callbacks(list of callables): callable to invoke before
            trying to run the DeleteStack call. Each callback is called with
            kwargs of ``stack_name``, and ``config``. (Python only, not setable from
            command line)
    """
    stack_name = get_stack_name()
    if not force:
        x = raw_input("Are you really sure you want to blow away the whole stack for {}!? (y/n)\n".format(stack_name))
        if x not in ['y', 'Y', 'Yes', 'yes']:
            sys.exit(1)
    cfn_config = get_config()
    cfn = get_connection(Cloudformation)

    if pre_delete_callbacks is not None:
        for callback in pre_delete_callbacks:
            callback(stack_name=stack_name, config=cfn_config)

    print green("\nSTACK {0} DELETING...\n").format(stack_name)

    cfn.delete(stack_name)

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
        logger.info("Reloading SSL certificates...")
        iam = get_connection(IAM)
        updated_count = iam.update_ssl_certificates(cfn_config.ssl(),
                                                    stack_name)
    else:
        logger.error("No ssl section found in cloud config file, aborting...")
        sys.exit(1)

    # Arbitrary wait to allow SSL upload to register with AWS
    # Otherwise, we can get an ARN for the load balancer certificates
    # without it being ready to assign
    time.sleep(3)

    # Set the certificates on ELB's if we have any
    if updated_count:
        if 'elb' in cfn_config.data:
            logger.info("Setting load balancer certificates...")
            elb = get_connection(ELB)
            elb.set_ssl_certificates(updated_count, stack_name)
    else:
        logger.error("No certificates updated so skipping "
                     "ELB certificate update...")


def get_cloudformation_tags():
    """
    Get a top-level set of tags for the stack, these will propagate
    down so that many of the created resources will be tagged in
    addition. Notable omissions are EBS volumes and route53 resources
    """
    return {
        "Env": env.environment,
        "Application": env.application
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


@task
def enable_vpc_peering():
    """
    Enables vpc peering to stacks named in the cloudformation config.
    """
    # peer vpc
    cfg = get_config()
    vpc_cfg = cfg.data.get('vpc', False)
    if vpc_cfg:
        vpc_obj = VPC(cfg.data, get_stack_name())
        vpc_obj.enable_peering()


@task
def disable_vpc_peering():
    """
    Disables vpc peering to stacks named in the cloudformation config.
    """
    # peer vpc
    cfg = get_config()
    vpc_cfg = cfg.data.get('vpc', False)
    if vpc_cfg:
        vpc_obj = VPC(cfg.data, get_stack_name())
        vpc_obj.disable_peering()


@task
def set_autoscaling_desired_capacity(capacity, block=True):
    """
   Set the desired capacity the autoscaling group

    Args:
        capacity(int): Number of instances desired in
            the autoscaling group.
        block(bool): Wait for instances to become healthy
            and in-service.
    """
    asg = get_connection(Autoscale)
    if not asg.group:
        asg.set_autoscaling_group(get_stack_name())
    asg.set_autoscaling_desired_capacity(capacity=int(capacity))
    if block:
        asg.wait_for_instances(int(capacity))


@task
def cycle_instances(delay=None):
    """
    Cycle the instances in the autoscaling group

    Args:
        delay(int): Number of seconds between new instance
            becoming healthy and killing the old one.
    """
    asg = get_connection(Autoscale)
    if not asg.group:
        asg.set_autoscaling_group(get_stack_name())
    if delay:
        termination_delay = int(delay)
    else:
        termination_delay = None
    asg.cycle_instances(termination_delay=termination_delay)
