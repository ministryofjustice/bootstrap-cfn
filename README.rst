.. image:: https://travis-ci.org/ministryofjustice/bootstrap-cfn.svg
    :target: https://travis-ci.org/ministryofjustice/bootstrap-cfn

.. image:: https://coveralls.io/repos/ministryofjustice/bootstrap-cfn/badge.svg?branch=master
    :target: https://coveralls.io/r/ministryofjustice/bootstrap-cfn?branch=master

Ministry of Justice - Cloudformation
====================================

The objective of this repo is to enable MoJ teams to create project infrastructure in a uniform manner. Currently this includes the following AWS services:

- EC2 Servers via Auto-Scaling Groups
- Elastic Load Balancers (ELB)
- Relational Database Service (RDS)
- S3 Storage for web static content

Installation
============
::

    git clone git@github.com:ministryofjustice/bootstrap-cfn.git
    cd bootstrap-cfn
    pip install -r requirements.txt


Developing and running tests
============================

The test suite can be run via setup.py as follows::

    python -m unittest discover

or::

    python setup.py test


Example Usage
=============

Bootstrap-cfn uses `fabric <http://www.fabfile.org/>`_, so if your ``$CWD`` is the root directory of bootstrap-cfn then you can run::

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml cfn_create


If your ``$CWD`` is anywhere else, you need to pass in a path to particular fabric file::

    fab -f /path/to/bootstrap-cfn/fabfile.py application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml cfn_create


- **application:courtfinder** - is just a name to associate with Cloudformation stack
- **aws:dev** - is a way to differentiate between AWS accounts (defined in ``~/.aws/credentials.yaml``)
- **environment:dev** - The key name to read in the file specified to the ``config`` task
- **config:/path/to/file.yaml** - The location to the project YAML file

Multiple Stacks
=================

If you want to run multiple stacks with the same name and environment place the following in the yaml configuration::

    master_zone:
      my-zone.dsd.io

Then when you create a stack you can specify a tag before cfn_create, like::

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml tag:active cfn_create

NB active is the default.

Then you can refer to this stack by it's tag in the future. In this way it is easier to bring up two stacks from the same config. If you want to swap the names of the stacks you can do the following::

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml swap_tags:inactive,active

Example Configuration
=====================
AWS Account Configuration
+++++++++++++++++++++++++

This tool needs AWS credentials to create stacks and the credentials should be placed in the ``~/.aws/credentials`` file (which is the same one used by the AWS CLI tools). You should create named profiles like this (and the section names should match up with what you specify to the fabric command with the ``aws:my_project_prod`` flag) ::


    [my_project_dev]
    aws_access_key_id = AKIAI***********
    aws_secret_access_key = *******************************************
    [my_project_prod]
    aws_access_key_id = AKIAI***********
    aws_secret_access_key = *******************************************

If you wish to authenticate to a separate AWS account using cross account IAM roles you should create a profile called `cross-account` with the access keys of the user with permission to assume roles from the second account::

    [cross-account]
    aws_access_key_id = AKIAI***********
    aws_secret_access_key = *******************************************

And when you run the tool you must set the ARN ID of the role in the separate account which you wish to assume. For example::

    AWS_ROLE_ARN_ID='arn:aws:iam::123456789012:role/S3Access' fab application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml cfn_create

Project specific YAML file
++++++++++++++++++++++++++
The `YAML file <https://github.com/ministryofjustice/bootstrap-cfn/blob/master/docs/sample-project.yaml>`_ highlights what is possible with all the bootstrap-cfn features available to date. The minimum requirement is that it must contain an *ec2* block, you **do not** have to use RDS, S3 or ELB's.

EC2 Auto-Scaling Groups
+++++++++++++++++++++++

The ``ec2`` key configures the EC2 instances created by auto-scaling groups (ASG) and their configuration. Note that we don't currently support auto-scaling properly, so if a scaling event happens the instances that come up will be unconfigured.

:``auto_scaling``:
  Configure the size of the auto scaling groups.

  ``desired``
    Target number of instances
  ``max``
    Maximum number of instances to scale up to
  ``min``
    Minimum number of instances to maintain.

  Example::

    dev:
      ec2:
        # …
        auto_scaling:
          desired: 1
          max: 3
          min: 0

:``tags``:
  A dictionary of tag name to value to apply to all instances of the ASG. Note that the environment you select via ``fab aws`` will be applied as a tag with a name of ``Env``.

  Example::

    dev:
      ec2:
        # …
        tags:
          Role: docker
          Apps: test
          # Env: dev # This is default if we are in the `dev` environment block.

:``parameters``:
  Configuration parameters to the ASG. Known keys:

  ``KeyName``
    Name of an existing key-pair in the SSH account to create add to the intial ssh user on instances
  ``InstanceType``
    The size of the EC2 instances to create

  Example::

    dev:
      ec2:
        # …
        parameters:
          KeyName: default
          InstanceType: t2.micro

:``block_devices``:
  A list of EBS volumes to create and attach to per instance. Each list should have

  ``DeviceName``
    The path of the linux device to attach the instance to
  ``VolumeSize``
    Size in gigabytes of the EBS volume

  Example::

    dev:
      ec2:
        # …
        block_devices:
          - DeviceName: /dev/sda1
            VolumeSize: 10
          - DeviceName: /dev/sdf
            VolumeSize: 100

:``security_groups``:
  Dictionary of security groups to create and add the EC2 instances to. The key is the name of the security group and the value is a list of ingress rules following the `Cloudformation reference <http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-ingress.html>`_

  Common options are

  ``IpProtocol``
    ``tcp``, ``udp``, or ``icmp``
  ``FromPort``
    Start of the port range or ICMP type to allow
  ``ToPort``
    End of the port range/ICMP type. Often the same as ``FromPort``
  ``CidrIp``
    An IP range to allow access to this port range.
  ``SourceSecurityGroupId``
    Allow access from members of this security group - which must exist in the same VPC. Use Ref (see example) to refer to a security group by name. Can be another SG referenced elsewhere or the same security group.

  One of ``CidrIp`` and ``SourceSecurityGroupId`` must be specified per rule (but not both).

  Example::

    dev:
      ec2:
        # …
        security_groups:
          # Don't to this - its too wide open
          SSH-from-anywhere:
            - IpProtocol: tcp
              FromPort: 22
              ToPort: 22
              CidrIp: 0.0.0.0/0
            - IpProtocol: tcp
              FromPort: 2222
              ToPort: 2222
              CidrIp: 0.0.0.0/0
          WebServer:
            # Allow acces to port 80 from the SG 
            - IpProtocol: tcp
              FromPort: 80
              ToPort: 80
              SourceSecurityGroupId: { Ref: DefaultSGtestdevexternal }
          Salt:
            # Allow all other members of the Salt sg to speak to us on 4505 and 4506
            - IpProtocol: tcp
              FromPort: 4505
              ToPort: 4506
              SourceSecurityGroupId: { Ref: Salt }

:``cloud_config``:
  Dictionary to be feed in via userdata to drive `cloud-init <http://cloudinit.readthedocs.org/en/latest/>`_ to set up the initial configuration of the host upon creation. Using cloud-config you can run commands, install packages

  There doesn't appear to be a definitive list of the possible config options but the examples are quite exhaustive:

  - `http://bazaar.launchpad.net/~cloud-init-dev/cloud-init/trunk/files/head:/doc/examples/`
  - `http://cloudinit.readthedocs.org/en/latest/topics/examples.html`_ (similar list but all on one page so easier to read)

:``hostname_pattern``:
  A python-style string format to set the hostname of the instance upon creation.

  The default is ``{instance_id}.{environment}.{application}``. To disable this entirely set this field explicitly to null/empty::

    dev:
      ec2:
        hostname_pattern:

  For ``sudo`` to not misbehave initially (because it cannot look up its own hostname) you will likely want to set ``manage_etc_hosts`` to true in the cloud_config section so that it will regenerate ``/etc/hosts`` with the new hostname resolving to 127.0.0.1.

  Setting the hostname is achived by adding a boothook into the userdata that will interpolate the instance_id correctly on the machine very soon after boottime.

  The currently support interpolations are:

  ``instance_id``
    The amazon instance ID
  ``environment``
    The enviroment currently selected (from the fab task)
  ``application``
    The application name (taken from the fab task)
  ``stack_name``
    The full stack name being created
  ``tags``
    A value from a tag for this autoscailing group. For example use ``tags[Role]`` to access the value of the ``Role`` tag.

  For example given this incomplete config::

    dev:
      ec2:
        # …
        hostname_pattern: "{instance_id}.{tags[Role]}.{environment}.{application}"
        tags:
          Role: docker
        cloud_config:
          manage_etc_hosts: true

  an instance created with ``fab application:myproject … cfn_create`` would get a hostname something like ``i-f623cfb9.docker.dev.my-project``.

ELBs
++++
By default the ELBs will have a security group opening them to the world on 80 and 443. You can replace this default SG with your own (see example ``ELBSecGroup`` above).

If you set the protocol on an ELB to HTTPS you must include a key called ``certificate_name`` in the ELB block (as example above) and matching cert data in a key with the same name as the cert under ``ssl`` (see example above). The ``cert`` and ``key`` are required and the ``chain`` is optional.

The certificate will be uploaded before the stack is created and removed after it is deleted.

It is possilbe to define a custom health check for an ELB like follows::

    health_check:
      HealthyThreshold: 5
      Interval: 10
      Target: HTTP:80/ping.json
      Timeout: 5
      UnhealthyThreshold: 2

Applying a custom s3 policy
+++++++++++++++++++++++++++
You can add a custom s3 policy to override bootstrap-cfn's default settings. For example, the sample custom policy defined in this `json file <https://github.com/ministryofjustice/bootstrap-cfn/blob/master/tests/sample-custom-s3-policy.json>`_ can be configured as follows:

::

   s3:
     static-bucket-name: moj-test-dev-static
     policy: tests/sample-custom-s3-policy.json

Includes
++++++++
If you wish to include some static cloudformation json and have it merged with the template generated by bootstrap-cfn. You can do the following in your template yaml file::

    includes:
      - /path/to/cloudformation.json

The tool will then perform a deep merge of the includes with the generated template dictionary. Any keys or subkeys in the template dictionary that clash will have their values **overwritten** by the included dictionary or recursively merged if the value is itself a dictionary.

ConfigParser
++++++++++++++
If you want to include or modify cloudformation resources but need to include some logic and not a static include. You can subclass the ConfigParser and set the new class as `env.cloudformation_parser` in your fabfile.


Enabling RDS encryption
+++++++++++++++++++++++
You can enable encryption for your DB by adding the following::
 
  rds:
     storage-encrypted: true
     instance-class: db.m3.medium

**NOTE:** AWS does not support RDS encryption for the *db.t2.** instance classes. More details on supported instance classes are available `here <http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html>`_


SSL cipher list pindown (updated 29/06/2015)
============================================
Amazon provides default policies for cipher lists:

* Type: SSLNegotiationPolicyType
* Name: Reference-Security-Policy

More info:

https://aws.amazon.com/blogs/aws/elastic-load-balancing-perfect-forward-secrecy-and-other-security-enhancements/

http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html

http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-ssl-security-policy.html

http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-table.html

The policy currently in use by default is: ELBSecurityPolicy-2015-05.

