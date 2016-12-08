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
- `VPC Configuration <docs/vpc-configuration.md>`_

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

    fab -f /path/to/bootstrap-cfn/fabfile.py application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml tag:test cfn_create


- **application:courtfinder** - is just a name to associate with Cloudformation stack
- **aws:dev** - is a way to differentiate between AWS accounts (defined in ``~/.aws/credentials.yaml``)
- **environment:dev** - The key name to read in the file specified to the ``config`` task
- **config:/path/to/file.yaml** - The location to the project YAML file
- **tag:test** - stack tag to differentiate between stacks
- **keyname:keyname** - the name of the keypair you uploaded in AWS which should store your SSH public key.

Multiple Stacks
===============

If you want to bring up a new stack as active stack, you will need to run the following fab tasks which we will explain later:

- **fab-env keyname:keyops tag:test cfn_create:** create a new stack with a tag and keyname specified.
- **fab-env -u ubuntu salt.wait_for_minions:** check if creation is done
- **fab-env -i ~/.ssh/id_your_ssh_private_key -u ubuntu update:** install salt on the stack, add admins from keys.sls
- **fab-env -u [your-ssh-name] update:** remove `ubuntu` user for security reason

Here `fab-env` refers to `fab application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml passwords:/path/to/courfinder-dev-secrets.yaml`.

So far A new stack should be created. You may want to set it to active stack of that environment:

**fab-env set_active_stack:[stack_tag]:** set active dns records in R53 


NB: If you want to run multiple stacks with the same name and environment place the following in the yaml configuration::

    master_zone:
      my-zone.dsd.io

cfn_create
----------

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml tag:active cfn_create

This is to create a stack based on your yaml configuration. After running the task, a stack name like `app-dev-e21e5110` should be created, along with two DNS records in Route 53 look like:

+------------------------------+------------+------------------------------------------------------------------------------------------------+
| Name                         | Type       | Value                                                                                          |
+==============================+============+================================================================================================+
| stack.test.blah-dev.dsd.io.  | **TXT**    | "e21e5110"                                                                                     |
+------------------------------+------------+------------------------------------------------------------------------------------------------+
| elbname-e21e5110.dsd.io.     | **A**      | ALIAS app-dev-elbname-1ocl2znar6wtc-1854012795.eu-west-1.elb.amazonaws.com. (z32o12xqlntsw2)   |
+------------------------------+------------+------------------------------------------------------------------------------------------------+

Note that:
- `test`in **TXT** record name is the stack tag you defined. An auto-generated stack id will be assigned to tag name if not specified. 
- `active` tag is **preserved** for setting the main entry point, so you should not use it as custom tag. 
- If the tag you specified already exists (may due to improper clean up in last creation), you could manually run `fab tag:[tag-name] cfn_delete` to remove them.

NB fab task `get_stack_list` returns all stacks of that application in case if you forgot your tag name :)



set_active_stack(tag_name)
--------------------------

An app's DNS entry is what your active stack at

After having created a new stack, you can set it to be the active stack simply by changing DNS records using ``set_active_stack(tag_name)``:

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml set_active_stack:[tag_name]

where [tag_name] would be the stack you would like to switch to.
NB this process will also automatically set deployarn record accordingly.


cfn_delete
----------

You can also delete any stack you want no more by specifying the tag::

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml tag:[tag_name] cfn_delete

NB ``tag_name`` can be any created tag. `active` is the default. 
When deleting an active stack, only active DNS records will be removed. Otherwise the whole stack along with dns records are being removed.

get_stack_list
++++++++++++++
    
    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml get_stack_list

This returns a list of all available stacks for specified application.

swap_tags
+++++++++

Then you can refer to this stack by its tag in the future. In this way it is easier to bring up two stacks from the same config. If you want to swap the names of the stacks you can do the following::

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml swap_tags:inactive, active


others
++++++

There are also some fab tasks for example ``get_active_stack`` that returns active stack for this application and environment; ``get_stack_list`` returns any related stacks.

Example Configuration
=====================
AWS Account Configuration
-------------------------

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
--------------------------
The `YAML file <https://github.com/ministryofjustice/bootstrap-cfn/blob/master/docs/sample-project.yaml>`_ highlights what is possible with all the bootstrap-cfn features available to date. The minimum requirement is that it must contain an *ec2* block, you **do not** have to use RDS, S3 or ELB's.

EC2 Auto-Scaling Groups
-----------------------

The ``ec2`` key configures the EC2 instances created by auto-scaling groups (ASG) and their configuration. Note that we don't currently support auto-scaling properly, so if a scaling event happens the instances that come up will be unconfigured.

:``auto_scaling``:
  Configure the size of the auto scaling groups.

  ``desired``
    Target number of instances
  ``max``
    Maximum number of instances to scale up to
  ``min``
    Minimum number of instances to maintain.
  ``health_check_grace_period``
    Seconds before running the healthcheck on an instance. Default 300
  ``health_check_type``
    Use EC2 or ELB healthcheck types. Default EC2

  Example::

    dev:
      ec2:
        # …
        auto_scaling:
          desired: 1
          max: 3
          min: 0
          health_check_grace_period: 360
          health_check_type: ELB

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

:``ami``:
  Selects which AWS AMI to use. This can be a AWS-provided AMI, a community one, or one which exists under the account in which you're building the stack. The ``ami-`` prefix is required. If not specified then a suitable default will be chosen for the ``os`` in use. If this value is present then it is recommended to specify the ``os`` too, so that other areas of the cloud formation template are correctly generated.

  Example::

    dev:
      ec2:
        ami: ami-7943ec0a
        os: windows2012

:``os``:
  Which operating system to use.  This selects a default AMI and also builds relevant user_data for use by instances when spun up by the ASG. Only 2 values are recognised: ``windows2012`` and ``ubuntu-1404``. The default is ``ubuntu-1404``.  If you wish to specify an AMI manually then use ``ami`` in addition.

  Example::

    dev:
      ec2:
        os: windows2012

:``block_devices``:
  A list of EBS volumes to create and attach to per instance. Each list should have

  ``DeviceName``
    The path of the linux device to attach the instance to
  ``VolumeSize``
    Size in gigabytes of the EBS volume
  ``VolumeType (optional)``
    The type of the volume to create. One of standard (default), gp2 or io1 (see `AWS API reference <http://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateVolume.html>`_)
  ``Iops (Required for io1 type)``
    The Iops value to assign to the io1 volume type.

  Example::

    dev:
      ec2:
        # …
        block_devices:
          - DeviceName: /dev/sda1
            VolumeSize: 10
          - DeviceName: /dev/sdf
            VolumeType: gp2
            VolumeSize: 100
          - DeviceName: /dev/sdh
            VolumeType: io1
            VolumeSize: 80
            Iops: 1200

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
          # Don't to this - it's too wide open
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
----
By default the ELBs will have a security group opening them to the world on 80 and 443. You can replace this default SG with your own (see example ``ELBSecGroup`` above).

If you set the protocol on an ELB to HTTPS you must include a key called ``certificate_name`` in the ELB block (as example above) and matching cert data in a key with the same name as the cert under ``ssl`` (see example above). The ``cert`` and ``key`` are required and the ``chain`` is optional.

It is possilbe to define a custom health check for an ELB like follows::

    health_check:
      HealthyThreshold: 5
      Interval: 10
      Target: HTTP:80/ping.json
      Timeout: 5
      UnhealthyThreshold: 2

ELB Certificates
++++++++++++++++

The SSL certificate will be uploaded before the stack is created and removed after it is deleted.
To update the SSL certificate on ELB listeners run the fab task below, this uploads and updates the
certificate on each HTTPS listener on your ELBs, by default the old certificate is deleted.

.. code:: bash

   fab load_env:<env_data> update_certs

Note that some errors appear in the log due to the time taken for AWS changes to propogate across infrastructure
elements, these are handled internally and are not neccessarily a sign of failure.

ELB Policies
++++++++++++

Policies can be defined within an ELB block, and optionally applied to a list of 
instance ports or load balancer ports.
The below example enable proxy protocol support on instance ports 80 and 443


.. code:: yaml

 policies:
   - name: EnableProxyProtocol
     type: ProxyProtocolPolicyType
     attributes:
       - ProxyProtocol: True
     # We can optionally define the instance or load_balancer ports
     # to here that the policy will be applied on
     instance_ports:
       - 80
       - 443
     #load_balancer_ports:
     #  - 80
     #  - 443

Elasticache
-----------

By specifying an elasticache section, a redis-backed elasticache replication group will be created. The group name will be available as an output.

::

   elasticache:                     # (REQUIRED) Main elasticache key, use {} for all default settings. Defaults are shown
      clusters: 3                   # (OPTIONAL) Number of one-node clusters to create
      node_type: cache.m1.small     # (OPTIONAL) The node type of the clusters nodes
      port: 6379                    # (OPTIONAL) Port number 
      seeds:                        # (OPTIONAL) List of arns to seed the database with
         s3:                        # (OPTIONAL) List of S3 bucket seeds in <bucket>/<filepath> format
            - "test-bucket-947923urhiuy8923d/redis.rdb"


S3
--

An s3 section can be used to create a StaticBucket, which is exposed by nginx, but default as /assets.
The bucket location will be by default public, with an output available of 'StaticBucketName'.
We can create the static bucket without any arguments, though this requires the use of {} as below.

::

   s3: {}   # Required if we have no keys and use all defaults
     
Or we can specify the name, and optionally a custom policy file if we want to to override bootstrap-cfn's default settings.
For example, the sample custom policy defined in this `json file <https://github.com/ministryofjustice/bootstrap-cfn/blob/master/tests/sample-custom-s3-policy.json>`_ can be configured as follows:


:: 

   s3: 
        static-bucket-name: moj-test-dev-static
        policy: tests/sample-custom-s3-policy.json
    
We can also supply a list of buckets to create a range of s3 buckets, these require a name. 
These entries can also specify their own policies or use the default, vpc limited one.

::

   s3:
      buckets:
         - name: mybucketid
           policy: some_policy
         - name: myotherbucketid

The outputs of these buckets will be the bucket name postfixed by 'BucketName', ie, mybucketidBucketName

Includes
--------
If you wish to include some static cloudformation json and have it merged with the template generated by bootstrap-cfn. You can do the following in your template yaml file::

    includes:
      - /path/to/cloudformation.json

The tool will then perform a deep merge of the includes with the generated template dictionary. Any keys or subkeys in the template dictionary that clash will have their values **overwritten** by the included dictionary or recursively merged if the value is itself a dictionary.

ConfigParser
------------
If you want to include or modify cloudformation resources but need to include some logic and not a static include. You can subclass the ConfigParser and set the new class as `env.cloudformation_parser` in your fabfile.


Enabling RDS encryption
-----------------------
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

