#!/usr/bin/env python

import sys
import random
import yaml

from bootstrap_cfn.config import ProjectConfig, ConfigParser
from bootstrap_cfn.cloudformation import Cloudformation
from bootstrap_cfn.ec2 import EC2
from bootstrap_cfn.iam import IAM

import os
from StringIO import StringIO

from fabric.api import env, task, sudo, put
from fabric.contrib.project import upload_project

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

    if not hasattr(env, 'stack_passwords'):
        env.stack_passwords = {}

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
    print "\n\nSTACK {0} DELETING...".format(stack_name)

    if hasattr(env, 'blocking') and env.blocking.lower() == 'false':
        print 'Running in non blocking mode. Exiting.'
        sys.exit(0)

    # Wait for stacks to delete
    print 'Waiting for stack to delete.'
    cfn.wait_for_stack_missing(stack_name)
    print "Stack successfully deleted"
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
    # print cfn_config.process()
    # Inject security groups in stack template and create stacks.
    stack = cfn.create(stack_name, cfn_config.process())
    print "\n\nSTACK {0} CREATING...".format(stack_name)

    if hasattr(env, 'blocking') and env.blocking.lower() == 'false':
        print 'Running in non blocking mode. Exiting.'
        sys.exit(0)

    # Wait for stacks to complete
    print 'Waiting for stack to complete.'
    cfn.wait_for_stack_done(stack)
    print 'Stacks completed, checking results.'
    stack_evt = cfn.get_last_stack_event(stack)
    print '{0}: {1}'.format(stack_evt.stack_name, stack_evt.resource_status)
    if stack_evt.resource_status == 'CREATE_COMPLETE':
        print 'Successfully built stack {0}.'.format(stack)
    else:
        print 'Failed to create stack: {0}'.format(stack)
        # So delete the SSL cert that we uploaded
        if 'ssl' in cfn_config.data:
            iam.delete_ssl_certificate(cfn_config.ssl(), stack_name)


@task
def find_master():
    stack_name = get_stack_name()
    ec2 = get_connection(EC2)
    master = ec2.get_master_instance(stack_name).ip_address
    print 'Salt master public address: {0}'.format(master)
    return master


def get_candidate_minions():
    stack_name = get_stack_name()
    cfn = get_connection(Cloudformation)
    ec2 = get_connection(EC2)
    instance_ids = cfn.get_stack_instance_ids(stack_name)
    stack_name = get_stack_name()
    master_instance_id = ec2.get_master_instance(stack_name).id
    instance_ids.remove(master_instance_id)
    return instance_ids


@task
def install_minions():
    stack_name = get_stack_name()
    ec2 = get_connection(EC2)
    print "Waiting for SSH on all instances..."
    ec2.wait_for_ssh(stack_name)
    candidates = get_candidate_minions()
    existing_minions = ec2.get_minions(stack_name)
    to_install = list(set(candidates).difference(set(existing_minions)))
    if not to_install:
        return
    public_ips = ec2.get_instance_public_ips(to_install)
    sha = '6080a18e6c7c2d49335978fa69fa63645b45bc2a'
    stack_name = get_stack_name()
    master_inst = ec2.get_master_instance(stack_name)
    master_public_ip = master_inst.ip_address
    master_prv_ip = master_inst.private_ip_address
    ec2.set_instance_tags(to_install, {'SaltMasterPrvIP': master_prv_ip})
    for inst_ip in public_ips:
        env.host_string = 'ubuntu@%s' % inst_ip
        sudo('wget https://raw.githubusercontent.com/ministryofjustice/bootstrap-cfn/master/scripts/bootstrap-salt.sh -O /tmp/moj-bootstrap.sh')
        sudo('chmod 755 /tmp/moj-bootstrap.sh')
        sudo('/tmp/moj-bootstrap.sh')
        sudo(
            'wget https://raw.githubusercontent.com/saltstack/salt-bootstrap/%s/bootstrap-salt.sh -O /tmp/bootstrap-salt.sh' %
            sha)
        sudo('chmod 755 /tmp/bootstrap-salt.sh')
        sudo(
            '/tmp/bootstrap-salt.sh -A `cat /etc/tags/SaltMasterPrvIP` git v2014.1.4')
        env.host_string = 'ubuntu@%s' % master_public_ip
        sudo('salt-key -y -A')


@task
def install_master():
    stack_name = get_stack_name()
    ec2 = get_connection(EC2)
    cfn = get_connection(Cloudformation)
    print "Waiting for SSH on all instances..."
    ec2.wait_for_ssh(stack_name)
    instance_ids = cfn.get_stack_instance_ids(stack_name)
    master_inst = ec2.get_master_instance(stack_name)
    master = master_inst.id if master_inst else random.choice(instance_ids)
    master_prv_ip = ec2.get_instance_private_ips([master])[0]
    master_public_ip = ec2.get_instance_public_ips([master])[0]
    ec2.set_instance_tags(instance_ids, {'SaltMasterPrvIP': master_prv_ip})
    ec2.set_instance_tags(master, {'SaltMaster': 'True'})

    stack_ips = ec2.get_instance_private_ips(instance_ids)
    stack_ips.remove(master_prv_ip)
    stack_public_ips = ec2.get_instance_public_ips(instance_ids)
    stack_public_ips.remove(master_public_ip)
    env.host_string = 'ubuntu@%s' % master_public_ip
    sha = '6080a18e6c7c2d49335978fa69fa63645b45bc2a'
    sudo('wget https://raw.githubusercontent.com/ministryofjustice/bootstrap-cfn/master/scripts/bootstrap-salt.sh -O /tmp/moj-bootstrap.sh')
    sudo('chmod 755 /tmp/moj-bootstrap.sh')
    sudo('/tmp/moj-bootstrap.sh')
    sudo(
        'wget https://raw.githubusercontent.com/saltstack/salt-bootstrap/%s/bootstrap-salt.sh -O /tmp/bootstrap-salt.sh' %
        sha)
    sudo('chmod 755 /tmp/bootstrap-salt.sh')
    sudo(
        '/tmp/bootstrap-salt.sh -M -A `cat /etc/tags/SaltMasterPrvIP` git v2014.1.4')
    sudo('salt-key -y -A')

@task
def rsync():
    if env.config is None:
        # check if there is a deploy repo in a predefined location
        app_yaml = '../{0}-deploy/{0}.yaml'.format(env.application)
        if os.path.exists(app_yaml):
            env.config = app_yaml

    _validate_fabric_env()

    work_dir = os.path.join('..', '{0}-deploy'.format(env.application))

    project_config = ProjectConfig(env.config, env.environment)
    stack_name = get_stack_name()
    cfg = project_config.config
    salt_cfg = cfg.get('salt', {})

    local_salt_dir = os.path.join(
        work_dir,
        salt_cfg.get('local_salt_dir', 'salt'),
        '.')
    local_pillar_dir = os.path.join(
        work_dir,
        salt_cfg.get('local_pillar_dir', 'pillar'),
        '.')
    local_vendor_dir = os.path.join(
        work_dir,
        salt_cfg.get('local_vendor_dir', 'vendor'),
        '.')

    remote_state_dir = salt_cfg.get('remote_state_dir', '/srv/salt')
    remote_pillar_dir = salt_cfg.get('remote_pillar_dir', '/srv/pillar')

    master_ip = find_master()
    env.host_string = '{0}@{1}'.format(env.user, master_ip)
    sudo('mkdir -p {0}'.format(remote_state_dir))
    sudo('mkdir -p {0}'.format(remote_pillar_dir))
    upload_project(
        remote_dir=remote_state_dir,
        local_dir=os.path.join(local_vendor_dir, '_root', '.'),
        use_sudo=True)
    upload_project(
        remote_dir='/srv/',
        local_dir=os.path.join(local_vendor_dir, 'formula-repos'),
        use_sudo=True)
    upload_project(
        remote_dir=remote_state_dir,
        local_dir=local_salt_dir,
        use_sudo=True)
    upload_project(
        remote_dir=remote_pillar_dir,
        local_dir=os.path.join(local_pillar_dir, env.environment, '.'),
        use_sudo=True)
    cf_sls = StringIO(yaml.dump(cfg))
    put(
        remote_path=os.path.join(
            remote_pillar_dir,
            'cloudformation.sls'),
        local_path=cf_sls,
        use_sudo=True)
