#!/usr/bin/env python

import logging
import os
import re
import sys
import uuid

import boto.exception

import boto3


from fabric.api import env, task
from fabric.colors import green, red, yellow
from fabric.utils import abort

import pkg_resources

from bootstrap_cfn.autoscale import Autoscale
from bootstrap_cfn.cloudformation import Cloudformation
from bootstrap_cfn.config import ConfigParser, ProjectConfig
from bootstrap_cfn.elb import ELB
from bootstrap_cfn.errors import (ActiveTagExistConflictError, BootstrapCfnError,
                                  CfnConfigError, CloudResourceNotFoundError, DNSRecordNotFoundError,
                                  StackRecordNotFoundError, TagRecordExistConflictError,
                                  TagRecordNotFoundError, UpdateDNSRecordError, UpdateDeployarnRecordError,
                                  ZoneIDNotFoundError)
from bootstrap_cfn.iam import IAM
from bootstrap_cfn.r53 import R53
from bootstrap_cfn.utils import strip_prefix, tail
from bootstrap_cfn.vpc import VPC


# Default fab config. Set via the tasks below or --set
env.setdefault('application')
env.setdefault('environment')
env.setdefault('aws')
env.setdefault('config')
env.setdefault('stack_passwords')
env.setdefault('blocking', True)
env.setdefault('aws_region', 'eu-west-1')
env.setdefault('keyname', None)

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
def aws(profile_name, region=None):
    """
    Set the AWS account to use

    Sets the environment variable 'aws' to the name of the
    account to use in the AWS config file (~/.aws/credentials.yaml)

    Args:
        profile_name(string): The string to set the environment
        variable to
        region(string): Override the region for the profile
    """
    default_region = env.aws_region
    env.aws = str(profile_name).lower()
    # If we are overriding the aws region, set it here,
    # otherwise, we will rely on the aws credentials setup
    if region is not None:
        env.aws_region = str(region).lower()
        logger.info("fab_tasks::aws: Setting profile {}, "
                    "region {}, and creating session..."
                    .format(env.aws, env.aws_region))
        boto3.setup_default_session(profile_name=env.aws,
                                    region_name=env.aws_region)
    else:
        boto3.setup_default_session(profile_name=env.aws)
        logger.info("fab_tasks::aws: No region specified, "
                    "using profile information only...")
    # If we have no default region in our credentials session,
    # set one.
    try:
        if boto3.DEFAULT_SESSION.region_name is not None:
            env.aws_region = boto3.DEFAULT_SESSION.region_name
        else:
            logger.info("fab_tasks::aws: No region found in credentials, "
                        "setting region to default, {}..."
                        .format(default_region))
            boto3.setup_default_session(profile_name=env.aws,
                                        region_name=default_region)
            env.aws_region = default_region
    except AttributeError:
        logger.info("fab_tasks::aws: No region found in credentials, "
                    "setting region to default, {}..."
                    .format(default_region))
        boto3.setup_default_session(profile_name=env.aws,
                                    region_name=default_region)
        env.aws_region = default_region


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
def keyname(keyname):
    """
    Sets the keyname to the keypair name on AWS

    Sets the keyname to specific keypair name you created instead of "default"
    Args:
        keyname: the name of keypair on AWS
    """
    env.keyname = str(keyname).lower()


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
    r53_conn.update_dns_record(zone_name, zone_id, record1, 'TXT', '"{0}"'.format(stack_suffix2))
    r53_conn.update_dns_record(zone_id, record2, 'TXT', '"{0}"'.format(stack_suffix1))


def apply_maintenance_criteria(elb):
    '''
    Applies maintenance criteria to elb

    Returns True if the maintenance should continue
    '''
    return elb['scheme'] == 'internet-facing'


@task
def enter_maintenance(maintenance_ip, dry_run=False):
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
        zone_id = get_cached_zone_id(r53_conn, cached_zone_ids, elb['hosted_zone'])
        zone_name = get_zone_name()
        print green("Attempting to update: \"{0}\":\"{1}\"".format(elb, maintenance_ip))
        r53_conn.update_dns_record(zone_name, zone_id, elb, 'A', maintenance_ip, dry_run=dry_run)


@task
def exit_maintenance(dry_run=False):
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
        (x.get('logical_resource_id', x.get('LogicalResourceId', None)),
         x.get('physical_resource_id', x.get('PhysicalResourceId', None)))
        for x in elb_conn.cfn.get_stack_load_balancers(stack_name)])
    if None in stack_elbs.keys():
        raise BootstrapCfnError(
            "Unable to retrieve logical resource IDs for a stack load balancer.\n"
            "ELB Dict: ".format(stack_elbs))
    if None in stack_elbs.values():
        raise BootstrapCfnError(
            "Unable to retrieve physical resource IDs for a stack load balancer.\n"
            "ELB Dict: ".format(stack_elbs))

    # filter stack related load balancers (as opposed to all stack elbs in the account)
    full_load_balancers = elb_conn.conn_elb.get_all_load_balancers(
        load_balancer_names=stack_elbs.values())

    cached_zone_ids = {}
    # loop through elb config entries and change internet facing ones
    for elb in cfn_config.data['elb']:
        if not apply_maintenance_criteria(elb):
            continue
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
        print green("Attempting to update: \"{0}\":{1}".format(elb, record_value))
        r53_conn.update_dns_record(zone_name, zone_id, elb, 'A', record_value, is_alias=True, dry_run=dry_run)


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

    try:
        stack_tag = get_env_tag()
    except AttributeError:
        stack_tag = 'active'
        env.tag = stack_tag
    if not hasattr(env, 'stack_name'):
        # get_config needs a stack_name so this is a hack because we don't
        # know it yet...
        env.stack_name = 'temp'
        zone_name = get_zone_name()
        zone_id = get_zone_id()
        logger.info("fab_tasks::get_stack_name: Found master zone '%s' in config...", zone_name)
        # get record name in the format of: stack.[stack_tag].[app]-[env]
        record_name = get_txt_record_name(stack_tag)
        dns_name = "{}.{}".format(record_name, zone_name)
        r53_conn = get_connection(R53)
        try:
            # get stack id
            stack_suffix = r53_conn.get_record(zone_name, zone_id, record_name, 'TXT').replace('"', "")
            logger.info("fab_tasks::get_stack_name: Found stack suffix '%s' "
                        "for dns record '%s'... ", stack_suffix, dns_name)
            legacy_name = get_legacy_name()
            env.stack_name = "{0}-{1}".format(legacy_name, stack_suffix)
            logger.info("fab_tasks::get_stack_name: Found stack name '%s'...", env.stack_name)
        except Exception:
            raise DNSRecordNotFoundError(dns_name)

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
    # create a stack id
    r53_conn = get_connection(R53)
    zone_name = get_zone_name()
    zone_id = get_zone_id()
    stack_suffix = uuid.uuid4().__str__()[-8:]
    try:
        stack_tag = get_env_tag()
        if stack_tag == 'active':
            # print red("'Active' tag is reserved, please change a tag. ")
            raise ActiveTagExistConflictError()
        elif r53_conn.hastag(zone_name, zone_id, get_txt_record_name(stack_tag)):
            # print red("{} exists, please change a tag. ".format(env.tag))
            raise TagRecordExistConflictError(stack_tag)
    except AttributeError:
        stack_tag = stack_suffix
        env.tag = stack_tag
    record = get_txt_record_name(stack_tag)
    logger.info("fab_tasks::set_stack_name: "
                "Creating stack suffix '%s' "
                "for record '%s' "
                "in zone id '%s'...", stack_suffix, record, zone_id)
    # Let DNS update DNSServerError propogate
    try:
        r53_conn.update_dns_record(zone_name, zone_id, record, 'TXT', '"{0}"'.format(stack_suffix))
        env.stack_name = "{0}-{1}".format(get_legacy_name(), stack_suffix)
    except Exception:
        raise UpdateDNSRecordError
    print green("Stack tag is set to {0}".format(stack_tag))
    return env.stack_name


def get_zone_name():
    try:
        zone_name = get_basic_config()['master_zone']
    except KeyError:
        raise CfnConfigError("No master_zone in yaml, unable to create/find DNS records for stack name")
    logger.info("fab_tasks::get_zone_id: Found master zone '%s' in config...", zone_name)
    return zone_name


def get_zone_id():
    zone_name = get_zone_name()
    r53_conn = get_connection(R53)
    try:
        zone_id = r53_conn.get_hosted_zone_id(zone_name)
    except Exception:
        raise ZoneIDNotFoundError(zone_name)
    logger.info("fab_tasks::get_zone_id: Found zone id '%s' "
                "for zone name '%s'...", zone_id, zone_name)
    return zone_id


def get_legacy_name():
    legacy_name = "{0}-{1}".format(env.application, env.environment)
    return legacy_name


def get_txt_record_name(stack_tag):
    """
    Returns record name in the format of: stack.[tag].[app]-[env]
    Args:
        stack_tag: the tag of stack
    Returns:
        record name like stack.[tag].[app]-[env]
    """
    legacy_name = get_legacy_name()
    record_name = "stack.{0}.{1}".format(stack_tag, legacy_name)
    return record_name


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


def get_config(called_by_cfn_create=False, stack_name=None):
    '''

    Args:
        called_by_cfn_create:
        stack_name: for some conditions when we know the stack name,
    we don't have to get it by requesting DNS records

    Returns:

    '''
    stack_name = stack_name or get_stack_name()
    Parser = env.get('cloudformation_parser', ConfigParser)
    basic_config = get_basic_config()
    # keyname is mandatory in cfn_create, optional in others.
    # keyname can be defined in fab or config while fab parameters has higher priority.
    # otherwise not.
    env_keyname = None
    if called_by_cfn_create:
        env_keyname = env.keyname
        if env.keyname is None:
            # if keyname is not defined in fab, check config file instead
            print "[WARNING] keyname is not specified in fab command, checking config file..."
            try:
                env_keyname = basic_config['ec2']['parameters']['KeyName']
            except KeyError:
                sys.exit("[ERROR] KeyName is not defined in config file. "
                         "Please specify via fab e.g 'keyname:opskey' or config file")
        print green("Creating stack with keyname: {0}").format(env_keyname)
    cfn_config = Parser(get_basic_config(), stack_name, environment=env.environment,
                        application=env.application, keyname=env_keyname)
    return cfn_config


def get_connection(klass):
    _validate_fabric_env()
    return klass(env.aws, env.aws_region)


@task
def cfn_delete(force=False, pre_delete_callbacks=None):
    """
    Delete the AWS Cloudformation stack for inactive stacks

    Delete DNS records for active stacks

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

    r53_conn = get_connection(R53)

    stack_id = stack_name.split('-')[-1]
    stack_tag = 'active' if isactive() else get_env_tag()

    zone_id = get_zone_id()
    zone_name = get_zone_name()

    try:
        txt_tag_record = get_txt_record_name(stack_tag)
        print green("\nDELETING TXT RECORDS {}-{}...\n".format(txt_tag_record, zone_name))
        r53_conn.delete_txt_record(zone_name, zone_id, txt_tag_record)
    except boto.route53.exception.DNSServerError:
            pass

    for elb in get_all_elbs():
        logger.info("Deleting '{}-{}' from '{}' ({})...".format(elb, stack_id, zone_name, zone_id))
        try:
            print green("\nDELETING Alias RECORDS {}-{}-{}...\n".format(elb, stack_id, zone_name))
            r53_conn.delete_alias_record(zone_name, zone_id, elb, stack_id, stack_tag)
        except boto.route53.exception.DNSServerError:
            pass

    if not isactive():
        print green("\nSTACK {0} DELETING...\n").format(stack_name)
        logger.info("Deleting inactive stack '{}' ({})...".format(stack_name, stack_tag))

        try:
            txt_arn_record = 'deployarn.{0}.{1}.{2}'.format(stack_tag, env.environment, env.application)

            txt_record_value = '"{}"'.format(r53_conn.get_record(zone_name, zone_id, txt_arn_record, 'TXT'))

            logger.info("Deleting '{}' from '{}' ({}) ...".format(txt_arn_record, zone_name, zone_id))
            r53_conn.delete_dns_record(zone_name, zone_id, txt_arn_record, 'TXT', txt_record_value)
        except boto.route53.exception.DNSServerError:
            pass

        print "Waiting for stack '{}' to be deleted...".format(stack_name)
        cfn.delete(stack_name)

        if env.blocking:
            try:
                tail(cfn, stack_name)
            except boto.exception.BotoServerError as e:
                if e.code == 'ValidationError':
                    pass
                raise e
            return True
        else:
            print 'Running in an non-blocking mode.'

        if cfn.stack_missing(stack_name):
            print green("Stack '{}' successfully deleted.".format(stack_name))
        else:
            print red("Failed to delete stack '{}' successfully.".format(stack_name))
            return False

        try:
            iam = get_connection(IAM)
            iam.delete_ssl_certificate(cfn_config.ssl(), stack_name)
        except AttributeError, boto.exception:
            print green("SSL certificate was already deleted.")
        except KeyError:
            print green("SSL does not exist in cloudformation configuration file")

    return True


def get_env_tag():
    return env.tag


def get_env_application():
    try:
        app = env.application
    except AttributeError:
        print red("Stack tag is not specified, please put application:[app-name]")
        exit(1)
    return app


def get_env_blocking():
    '''
    for the convenience of using mock.patch in unittest
    Returns:

    '''

def isactive():
    try:
        if env.tag == 'active':
            return True
    except AttributeError:
        return False


@task
def cfn_update(test=False):
    """
    Update the AWS cloudformation stack.
    """
    _validate_fabric_env()
    stack_name = get_stack_name(new=False)
    cfn_config = get_config(called_by_cfn_create=True)

    cfn = get_connection(Cloudformation)
    # Get online template
    response = cfn.conn_cfn.get_template(stack_name)
    body = response['GetTemplateResponse']['GetTemplateResult']['TemplateBody']
    new_body = cfn_config.process_update(body)

    x = raw_input("Are you sure you want to update the stack {}!? (y/n)\n".format(stack_name))
    if x not in ['y', 'Y', 'Yes', 'yes']:
        sys.exit(1)

    rc = cfn.update(stack_name, cfn_config.process_update(body))
    if not rc:
        logger.critical("cfn_update: please check the logs for BotoServerError criticals")
        logger.critical("cfn_update: this usually happens when cfn_update is ran but no changes are needed")
        return

    tail(cfn, stack_name)
    return True

@task
def cfn_create(test=False):
    """
    Create the AWS cloudformation stack.

    Using the configuration files, a full cloudformation
    specification will be generated and used to create a
    stack on AWS.
    """
    _validate_fabric_env()
    stack_name = get_stack_name(new=True)
    cfn_config = get_config(called_by_cfn_create=True)

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
    except Exception:
        # cleanup ssl certificates if any
        if 'ssl' in cfn_config.data:
            print red("Deleting SSL certificates from stack")
            iam.delete_ssl_certificate(cfn_config.ssl(), stack_name)
        import traceback
        red("Failed to create: {error}".format(error=traceback.format_exc()))
        red("Deleting stack and aborting...)")
        cfn_delete(True)
        abort(red("Aborted..."))

    print green("\nSTACK {0} CREATING...\n").format(stack_name)
    if not env.blocking:
        print 'Running in non blocking mode. Exiting.'
        sys.exit(0)

    tail(cfn, stack_name)
    stack_evt = cfn.get_last_stack_event(stack)

    if stack_evt.resource_status == 'CREATE_COMPLETE':
        print green('Successfully built stack {0}.'.format(stack))
    else:
        # So delete the SSL cert that we uploaded
        if 'ssl' in cfn_config.data:
            iam.delete_ssl_certificate(cfn_config.ssl(), stack_name)
        abort('Failed to create stack: {0}'.format(stack))
    return True


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
    iam = get_connection(IAM)
    # Upload any SSL certificates to our EC2 instances
    if 'ssl' in cfn_config.data:
        logger.info("Reloading SSL certificates...")
        updated_count = iam.update_ssl_certificates(cfn_config.ssl(),
                                                    stack_name)
    else:
        logger.error("No ssl section found in cloud config file, aborting...")
        sys.exit(1)

    # Set the certificates on ELB's if we have any
    if updated_count:
        if 'elb' in cfn_config.data:
            logger.info("Setting load balancer certificates...")
            elb = get_connection(ELB)
            replaced_certs = elb.set_ssl_certificates(updated_count,
                                                      stack_name,
                                                      max_retries=3,
                                                      retry_delay=10)
            for cert_name in replaced_certs:
                logger.info("Deleting replaced certificate '%s'..."
                            % (cert_name))
                iam.delete_certificate(cert_name,
                                       stack_name,
                                       max_retries=3,
                                       retry_delay=10)
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
        "Application": env.application,
        "Bootstrap-cfn-Version":  pkg_resources.require("bootstrap-cfn")[0].version
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


@task
def set_active_stack(stack_tag, force=False):
    """
    Switch between stacks tagged differently
    Update 'active' stacks' DNS records to the one specified.
    Args:
        stack_tag: the tag of stack to be active
        force: if True, set it to active stack directly
    """
    # helloworld.active.dsd.io
    active_record = get_txt_record_name('active')
    r53_conn = get_connection(R53)
    zone_name = get_zone_name()
    zone_id = get_zone_id()

    # stack_tag is used to set active deploy arn
    if stack_tag is None:
        print red("Stack tag cannot be 'None', please specify it")
        sys.exit(1)
    tag_record = get_txt_record_name(stack_tag)

    tag_stack_id = r53_conn.get_record(zone_name, zone_id, tag_record, 'TXT')
    if not tag_stack_id:
        raise TagRecordNotFoundError(tag_record)

    if get_active_stack() and not force:
        x = raw_input("Your stack is {}. Do you want to change? (y/n)\n".format(tag_stack_id))
        if x not in ['y', 'Y', 'Yes', 'yes']:
            sys.exit(1)

    try:
        set_active_deployarn(stack_tag)
    except Exception:
        raise UpdateDeployarnRecordError()
    try:
        r53_conn.update_dns_record(zone_name, zone_id, active_record, 'TXT',
                                   '"{}"'.format(tag_stack_id))
        logger.info("fab_tasks::set_active_stack: Successfully updated DNS "
                    "alias record for stack: %s", tag_stack_id)
    except Exception:
        raise UpdateDNSRecordError

    elbs = get_all_elbs()
    logger.info('fab_tasks::set_active_stack: Found ELBs matching the stack: %s',
                ', '.join(elbs))
    for elb in elbs:
        record_name = "{}-{}".format(elb, tag_stack_id)
        try:
            record_object = r53_conn.get_full_record(zone_name, zone_id, record_name, 'A')
            record_value = [record_object.alias_hosted_zone_id,
                            record_object.alias_dns_name,
                            record_object.alias_evaluate_target_health]
            try:
                r53_conn.update_dns_record(zone_name, zone_id, elb, 'A',
                                           record_value, is_alias=True)
                logger.info("fab_tasks::set_active_stack: Successfully "
                            "updated DNS alias record for ELB: %s", elb)
            except Exception:
                raise UpdateDNSRecordError
        except Exception:
            raise StackRecordNotFoundError(record_name)

    print green("Active stack switched to '{}' ({}).".format(tag_record, tag_stack_id))
    return True


def set_active_deployarn(stack_tag):
    """
    - Get the value of delpoyarn.stack_tag.x.x
    - Set it to the value of deployarn.active.x.x
    Args:
        stack_tag: the stack that is set to be active

    Returns:
        (String) AWS arn value
    """
    zone_name = get_zone_name()
    tag_arn_record = arn_record_name(stack_tag)
    active_arn_record = arn_record_name('active')
    zone_id = get_zone_id()
    r53 = get_connection(R53)
    try:
        tag_arn_value = r53.get_deployarn_record(zone_name, zone_id, tag_arn_record, 'TXT')
        if tag_arn_value is None:
            raise StackRecordNotFoundError('{}. Make sure you run "set_deploy_arn" on {}'
                                           ' before set_active_stack'.format(tag_arn_value), stack_tag)
        try:
            ret = r53.update_dns_record(zone_name, zone_id, active_arn_record, 'TXT', '"{0}"'.format(tag_arn_value))
            print "Active deployarn was set to: {0}".format(tag_arn_value)
        except:
            raise UpdateDeployarnRecordError
    except:
        raise StackRecordNotFoundError(tag_arn_record)
    return ret


def arn_record_name(stack_tag):
    tag_arn_record = 'deployarn.{0}.{1}.{2}'.format(stack_tag,
                                                    env.environment,
                                                    env.application)
    return tag_arn_record


@task
def get_active_stack():
    """
    Returns stack id if active stack exists AND Alias record is set appropriately
    """

    r53_conn = get_connection(R53)

    prefix = r'dualstack.'
    suffix = r'.+\.amazonaws.com\.?$'

    try:
        zone_id = get_zone_id()
        zone_name = get_zone_name()
        active_record = get_txt_record_name('active')
        active_stack_id = r53_conn.get_record(zone_name, zone_id, active_record, 'TXT')

        records = []
        for elb in get_all_elbs():
            dns_record_name = '{}-{}'.format(elb, active_stack_id)

            main_record_value = r53_conn.get_record(zone_name, zone_id, elb, 'A')
            dns_record_value = r53_conn.get_record(zone_name, zone_id, dns_record_name, 'A')

            if re.match(suffix, main_record_value):
                main_record_value = strip_prefix(main_record_value, prefix)

            if re.match(suffix, dns_record_value):
                dns_record_value = strip_prefix(dns_record_value, prefix)

            records += [dns_record_value, main_record_value == dns_record_value]

    except Exception:
        print yellow("No active stack exists.")
        return

    if active_stack_id and all(records):
        print green("Active stack id is: {}".format(active_stack_id))
        return active_stack_id
    else:
        print yellow("No active stack exists.")


def get_all_elbs(f=None):
    """
    Returns a list of internet-facing and internal ELBs from the CloudFormation
    configuration containing items for which the filter function f
    returns True, or everything.
    """
    cfn_config = get_config()
    elbs = [x.get('name') for x in cfn_config.data.get('elb', {}) if x.get('scheme') in ['internet-facing', 'internal']]
    return filter(f, elbs) if f else elbs


def get_public_elbs(stack, f=None):
    """
    Returns a list of internet-facing ELBs from the CloudFormation
    configuration containing items for which the filter function f
    returns True, or everything.
    """
    cfn_config = get_config(stack_name=stack)
    elbs = [x.get('name') for x in cfn_config.data.get('elb', {}) if x.get('scheme') == 'internet-facing']
    return filter(f, elbs) if f else elbs


def get_first_public_elb():
    """
    Returns the first public ELB if exists or None.
    """
    elbs = get_public_elbs()
    return next(iter(elbs), None)


@task
def get_stack_list():
    '''
    Returns all stacks in all environments

    '''
    r53_conn = get_connection(R53)
    cfn = get_connection(Cloudformation)
    rrsets = r53_conn.get_all_resource_records(get_zone_id())
    regex = "stack\.\w+\.{}.+".format(get_env_application())
    stack_count = 0
    stacks_list = []
    leftover_dns = []
    for rr in rrsets:
        if re.match(regex, rr.name):
            stack_id = rr.resource_records[0][1:-1]
            dns_record_name = rr.name
            # get stack name from dns record
            stack_name_prefix = dns_record_name.split('.')[2]
            stack_tag = dns_record_name.split('.')[1]
            stack_name = "{0}-{1}".format(stack_name_prefix, stack_id)
            stack_count += 1
            if not cfn.stack_missing(stack_name):
                stacks_list.append("{} | {}".format(dns_record_name.ljust(50), stack_name.ljust(50)))
            else:
                leftover_dns.append("{} | {}".format(dns_record_name.ljust(50), stack_tag.ljust(50)))
    print green("{} | {}".format("DNS Record".ljust(50), "Stack Name".ljust(50)))
    print '\n'.join(s for s in stacks_list)
    print yellow("{} | {}".format("Leftover DNS Record".ljust(50), "Stack Tag".ljust(50)))
    print '\n'.join(l for l in leftover_dns)
    return stack_count


@task(alias='oldfriendly')
def support_old_bootstrap_cfn(stack_name=None):
    '''
    Add DNS records for old stacks to support 1.x.x bootstrap-cfn

    If stack exists but no active records, add active records(TXT & ELB) and continue;
    If stack and active records exists, add sub records if they don't

    Args:
        stack_name: the stack you want to upgrade boootstrap-cfn. we don't use get_stack_name()
        as it requires the stack record which doesn't exist.
    Returns:
        True:
        Exceptions:

    '''
    # list stacks
    get_stack_list()
    if stack_name is None:
        stack_name = raw_input("Please specify the stack name: [q/n] to exit\n")
        if stack_name in ['q','n']:
            exit(1)

    try:
        stack_tag = get_env_tag()
    except AttributeError:
        stack_tag = raw_input("Give this stack a tag, or [q/n] to exit \n")
        if stack_name in ['q','n']:
            exit(1)
        print green("{} is tagged as {}".format(stack_name, stack_tag))
    stack_id = stack_name.split('-')[-1]
    r53_conn = get_connection(R53)
    zone_name = get_zone_name()
    zone_id = get_zone_id()
    cfn_conn = get_connection(Cloudformation)

    # if stack doesn't exist
    if cfn_conn.stack_missing(stack_name):
        print red("Stack '{}' does not exist".format(stack_name))
        return False

    # if stack exists:
    active_record_name = get_txt_record_name("active")
    stack_record_name = get_txt_record_name(stack_tag)
    try:
        active_record_value = r53_conn.get_record(zone_name, zone_id, active_record_name, 'TXT')
    except boto.exception:
        raise DNSRecordNotFoundError("%s", active_record_name)
    if active_record_value is None:
        # if active records don't exist, create both active and sub records
        for record in [active_record_name, stack_record_name]:
            r53_conn.update_dns_record(zone_name, zone_id, record, 'TXT', '"{0}"'.format(stack_id))
    # check if stack records exist already
    # create one if doesn't
    try:
        stack_record_value = r53_conn.get_record(zone_name, zone_id, stack_record_name, 'TXT')
    except boto.exception:
        raise DNSRecordNotFoundError("%s", stack_record_name)
    if stack_record_value is None:
        r53_conn.update_dns_record(zone_name, zone_id, stack_record_name, 'TXT', '"{0}"'.format(stack_id))

    # Alias records
    active_elb_names = get_public_elbs(stack_name)
    for active_elb_name in active_elb_names:
        try:
            active_elb_value_object = r53_conn.get_full_record(zone_name,
                                                               zone_id,
                                                               active_elb_name,
                                                               'A')
        except:
            raise DNSRecordNotFoundError("%s", active_elb_name)
        try:
            # if active elb exists
            active_elb_value = [active_elb_value_object.alias_hosted_zone_id,
                                active_elb_value_object.alias_dns_name,
                                active_elb_value_object.alias_evaluate_target_health]
        except AttributeError:
            # if active_elb_value_object is None
            raise DNSRecordNotFoundError("%s", active_elb_name)
        stack_elb_name = "{}-{}".format(active_elb_name, stack_id)
        # check if stack elb exists already
        # create one if doesn't
        try:
            stack_elb_value = r53_conn.get_full_record(zone_name, zone_id, stack_elb_name, 'A')
            if stack_elb_value is None:
                r53_conn.update_dns_record(zone_name, zone_id, stack_elb_name, 'A',
                                           active_elb_value, is_alias=True)
                logger.info("fab_tasks::support_old_bootstrap_cfn: Successfully "
                            "updated DNS alias record for ELB: %s", stack_elb_name)
        except boto.exception:
            raise UpdateDNSRecordError("%s", stack_elb_name)
    return True

