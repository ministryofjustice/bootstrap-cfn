# flake8: noqa
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

.. code:: bash

    git clone git@github.com:ministryofjustice/bootstrap-cfn.git
    cd bootstrap-cfn
    pip install -r requirements.txt


Developing and running tests
============================

The test suite can be run via setup.py as follows

.. code:: bash

    python -m unittest discover

or

.. code:: bash

    python setup.py test

Example Usage
=============

Bootstrap-cfn uses `fabric <http://www.fabfile.org/>`_, so if your ``$CWD`` is the root directory of bootstrap-cfn then you can run

.. code:: bash

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml cfn_create


If your ``$CWD`` is anywhere else, you need to pass in a path to particular fabric file

.. code:: bash

    fab -f /path/to/bootstrap-cfn/fabfile.py application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml tag:test cfn_create


- **application:courtfinder** - is just a name to associate with Cloudformation stack
- **aws:dev** - is a way to differentiate between AWS accounts (defined in ``~/.aws/credentials.yaml``)
- **environment:dev** - The key name to read in the file specified to the ``config`` task
- **config:/path/to/file.yaml** - The location to the project YAML file
- **tag:test** - stack tag to differentiate between stacks
- **keyname:keyname** - the name of the keypair you uploaded in AWS which should store your SSH public key.

Multiple Stacks
===============

Multiple stacks feature is supported in bootstrap-cfn version greater than 1.0.0. It is similar to Blue/Green deploy.
For each application and each environment of the application, we could have more than one stack independently running on AWS differentiated by tags we give.
Any existing stack of same application in same environment can be switched to 'active' via operations on R53 records, which is used as actioning stack.

Here are the steps to create a new stack, we will explain them one by one later:

- **fab-env keyname:keyops tag:mytag cfn_create:** create a new stack with a tag and keyname specified.
- **fab-env -u ubuntu salt.wait_for_minions:** (optional) wait until instances are ready
- **fab-env -i ~/.ssh/id_your_ssh_private_key -u ubuntu update:** install salt on the stack, add admins from keys.sls, to make the stack ready
- **fab-env -u [your-ssh-name] update:** remove `ubuntu` user from the instances for security reason

Here `fab-env` refers to `fab application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml passwords:/path/to/courfinder-dev-secrets.yaml`.

If you would like to set the stack you just created as the active stack of that environment, run the following:

- **fab-env set_active_stack:mytag** to switch DNS entry to this stack


NB: If you want to have your multiple stacks under the same zone, make sure specify it in the yaml configuration

.. code:: yaml

    master_zone:
      my-zone.dsd.io

cfn_create
----------

This is to create a stack based on your yaml configuration.

.. code:: bash

    fab application:app aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml tag:mytag cfn_create


After running the above, stack `app-dev-e21e5110` should be created, where 'e21e5110' is an auto-generated stack-id,
along with two DNS records in Route 53 that looks like:

+------------------------------+------------+------------------------------------------------------------------------------------------------+
| Name                         | Type       | Value                                                                                          |
+==============================+============+================================================================================================+
| stack.mytag.blah-dev.dsd.io.  | **TXT**    | "e21e5110"                                                                                     |
+------------------------------+------------+------------------------------------------------------------------------------------------------+
| elbname-e21e5110.dsd.io.     | **A**      | ALIAS app-dev-elbname-1ocl2znar6wtc-1854012795.eu-west-1.elb.amazonaws.com. (z32o12xqlntsw2)   |
+------------------------------+------------+------------------------------------------------------------------------------------------------+

Note that:

- `mytag` in **TXT** record name is the tag for the stack. An auto-generated stack id that's saved in Value is used as the tag if it's not specified.
- `active` tag is **preserved** for setting the main entry point, so you should not use it as a customised tag.
- If the tag you specified already exists (may due to improper clean up in last creation), you could manually run `fab tag:[tag-name] cfn_delete` to remove the leftover.

NB fab task `get_stack_list` returns all stacks of that application in case if you forgot your tag name :)



set_active_stack(tag_name)
--------------------------

Active records indicate where an app's DNS entry is.

you can set whichever existing stack to be the active stack simply by specifying the tag name in ``set_active_stack(tag_name)``

.. code:: bash

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml set_active_stack:[tag_name]

where [tag_name] would be the stack you would like to switch to.
NB this process will also automatically set deployarn record accordingly.


cfn_delete
----------

You can also delete any stack you want no more by specifying the tag, or remove active records (entry points) by putting active as the tag.

.. code:: bash

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml tag:[tag_name] cfn_delete

NB ``tag_name`` can be any existing tag. It defaults to `active`.
When deleting an active stack, only active DNS records will be removed without harming any existing stacks. Otherwise the whole stack along with dns records are being removed.

cfn_update
----------

Partial support for cloudformation updates is also supported on the EC2 and ELB sections of the configuration file.

.. code:: bash

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml tag:[tag_name] cfn_update

NB Running this command will show you some structured output of what
changes and how. Also a unified diff is printed on output between the
old and the new Launch Configuration sections. Although we have gone
to great lengths with this command, it can result in destructive
operations, particularly if one reduced the desired/max/min capacities
of the Auto Scaling Group.


get_stack_list
---------------

This returns a list of all available stacks for specified application.

.. code:: bash

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml get_stack_list

support_old_bootstrap_cfn
-------------------------

After bootstrap-cfn 1.0.0, we suggest multiple stacks which add another set of R53 records to each stack.
For stacks created by old bootstrap-cfn which possibly only has active records, `support_old_bootstrap_cfn` adds what's missing in R53
so that you are able to use other commands in bootstrap-cfn>=v1.0.0. It basically automates the manual operations of adding missing R53 records.

.. code:: bash

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml support_old_bootstrap_cfn

NB: after running this command, you will be asked to give the name of the stack you would like to operate on and also give a tag to the stack.

swap_tags
+++++++++

Then you can refer to this stack by its tag in the future. In this way it is easier to bring up two stacks from the same config. If you want to swap the names of the stacks you can do the following

.. code:: bash

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

  Example

.. code:: yaml

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

  Example

.. code:: yaml

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

  Example

.. code:: yaml

    dev:
      ec2:
        # …
        parameters:
          KeyName: default
          InstanceType: t2.micro

:``ami``:
  Selects which AWS AMI to use. This can be a AWS-provided AMI, a community one, or one which exists under the account in which you're building the stack. The ``ami-`` prefix is required. If not specified then a suitable default will be chosen for the ``os`` in use. If this value is present then it is recommended to specify the ``os`` too, so that other areas of the cloud formation template are correctly generated.


  Example

.. code:: yaml

    dev:
      ec2:
        ami: ami-7943ec0a
        os: windows2012

:``os``:
  Which operating system to use.  This selects a default AMI and also builds relevant user_data for use by instances when spun up by the ASG. Only 2 values are recognised: ``windows2012`` and ``ubuntu-1404``. The default is ``ubuntu-1404``.  If you wish to specify an AMI manually then use ``ami`` in addition.


  Example

.. code:: yaml

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


  Example

.. code:: yaml

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


  Example

.. code:: yaml

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
  - `http://cloudinit.readthedocs.org/en/latest/topics/examples.html` (similar list but all on one page so easier to read)

:``hostname_pattern``:
  A python-style string format to set the hostname of the instance upon creation.

  The default is ``{instance_id}.{environment}.{application}``. To disable this entirely set this field explicitly to null/empty

  Example

.. code:: yaml

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

  For example given this incomplete config

.. code:: yaml

    dev:
      ec2:
        # …
        hostname_pattern: "{instance_id}.{tags[Role]}.{environment}.{application}"
        tags:
          Role: docker
        cloud_config:
          manage_etc_hosts: true

an instance created with ``fab application:myproject … cfn_create`` would get a hostname something like ``i-f623cfb9.docker.dev.my-project``.

ALBS (ELBv2)
------------

AWS Application Load Balancers (ELBv2) are now supported by using a
very similar configuration scheme to the normal ELBs.

.. code:: yaml
   staging:
     alb:
    - name: tax-tribunals-datacapture-dev
      # This zone and the ones listed below must exist in the AWS
      # account you are using.
      hosted_zone: dsd.io.
      #
      # Optional. Self explanatory. If an entry is missing the
      # hosted_zone key then we automatically create a record set on the
      # hosted_zone of the main name
      #
      additional_hostnames:
         - name: name1
           hosted_zone: dsd.io
         - name: name2
           hosted_zone: dsd2.service.gov.uk
	 - name: name3
      scheme: internet-facing || internal
      certificate_name: acm_certificate_name
      listeners:
        - LoadBalancerPort: 80
          Protocol: HTTP
        - LoadBalancerPort: 443
          Protocol: HTTPS
      # This section can be omitted. These are the default values.
      target_group:
        Port: 80
	Protocol: HTTP
	HealthCheckProtocol: HTTP
	HealthCheckPort: 80
	HealthCheckPath: /
        HealthyThresholdCount: 5
        UnhealthyThresholdCount: 2
        HealthCheckTimeoutSeconds: 5
	HealthyHTTPCodes: 200 # 201,202,210-220

When ALBSs are used, a default Target Group is created (expecting port
80 to be listening by default on the internal hosts, altough this can
be customized) and a default Rule sending all traffic to this Target
Group.

If additional_hostnames are defined additional R53 records will be
created on the specified hosted_zones. In order for this feature to
work with different applications colocated on the same stack, all
instances of the ASG/Target Group need to have appropriate nginx
configuration implementing virtual hosts using the defined hostnames.s



ELBs
----
By default the ELBs will have a security group opening them to the world on 80 and 443. You can replace this default SG with your own (see example ``ELBSecGroup`` above).

If you set the protocol on an ELB to HTTPS you must include a key called ``certificate_name`` in the ELB block (as example above) and matching cert data in a key with the same name as the cert under ``ssl`` (see example above). The ``cert`` and ``key`` are required and the ``chain`` is optional.

It is possilbe to define a custom health check for an ELB like follows

.. code:: yaml

    health_check:
      HealthyThreshold: 5
      Interval: 10
      Target: HTTP:80/ping.json
      Timeout: 5
      UnhealthyThreshold: 2

ELB Certificates
++++++++++++++++

ACM
~~~

This section defines certificates for the AWS Certificate Manager. For verification, these will require the setting up of SES for the ValidationDomain so that emails to admin@<validation_domain> can be received.

.. code:: yaml
        acm:
          <certificate_name>:                           # (required) Alphanumeric resource name for the certificate
            domain: <domain_name>                       # (required) The domain name or wildcard the certificate should cover
                subject_alternative_names:              # (optional) List of alternative names the certificate should cover.
                    - <alternative_name_1>
                    - <alternative_name_2>
                validation_domain: <validation_domain>  # (optional) The domain name the verfication email should go to. The default is the domain name.
                tags:
                    <key>: <val>                      # (optional) Dictionary of keypairs to tag the resource with.

For example,

.. code:: yaml

        acm:
          mycert:
            domain: helloworld.test.dsd.io
            subject_alternative_names:
                - goodbye.test.dsd.io
            validation_domain: dsd.io
            tags:
                site: testsite

Manual SSL
~~~~~~~~~~

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


.. code:: yaml

   s3:
        static-bucket-name: moj-test-dev-static
        policy: tests/sample-custom-s3-policy.json

We can also supply a list of buckets to create a range of s3 buckets, these require a name.
These entries can also specify their own policies or use the default, vpc limited one.

.. code:: yaml

   s3:
      buckets:
         - name: mybucketid
           policy: some_policy
           lifecycles:
             /prefix1:
               expirationdays: 60
             /prefix2:
               expirationdays: 30
         - name: myotherbucketid
           lifecycles:
             /:
             expirationdays: 5

The outputs of these buckets will be the bucket name postfixed by 'BucketName', ie, mybucketidBucketName. Additionally, and as shown above, one can define a list of Lifecycle rules on a per prefix basis. If a root rule is defined, the rest of the rules are ignored.

Currently, only non-versioned buckets are supported.

Includes
--------
If you wish to include some static cloudformation json and have it merged with the template generated by bootstrap-cfn. You can do the following in your template yaml file

.. code:: yaml

    includes:
      - /path/to/cloudformation.json

The tool will then perform a deep merge of the includes with the generated template dictionary. Any keys or subkeys in the template dictionary that clash will have their values **overwritten** by the included dictionary or recursively merged if the value is itself a dictionary.

ConfigParser
------------
If you want to include or modify cloudformation resources but need to include some logic and not a static include. You can subclass the ConfigParser and set the new class as `env.cloudformation_parser` in your fabfile.


Enabling RDS encryption
-----------------------
You can enable encryption for your DB by adding the following

.. code:: yaml

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

* https://aws.amazon.com/blogs/aws/elastic-load-balancing-perfect-forward-secrecy-and-other-security-enhancements/
* http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html
* http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-ssl-security-policy.html
* http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-table.html

The policy currently in use by default is: ELBSecurityPolicy-2015-05.
