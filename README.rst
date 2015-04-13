.. image:: https://travis-ci.org/ministryofjustice/bootstrap-cfn.svg
    :target: https://travis-ci.org/ministryofjustice/bootstrap-cfn

.. image:: https://coveralls.io/repos/ministryofjustice/bootstrap-cfn/badge.svg?branch=master
    :target: https://coveralls.io/r/ministryofjustice/bootstrap-cfn?branch=master

Ministry of Justice - Cloudformation
=====================================

The objective of this repo is to enable MoJ teams to create project infrastructure in a uniform manner. Currently this includes the following AWS services:

- EC2 Servers
- Elastic Load Balancers (ELB)
- Relational Database Service (RDS)
- S3 Storage for web static content

Installation
=============
::

    git clone git@github.com:ministryofjustice/bootstrap-cfn.git
    cd bootstrap-cfn
    pip install -r requirements.txt


Developing and running tests
=============================

The test suite can be run via setup.py as follows::

    python -m unittest discover

or::

    python setup.py test


Example Usage
==============

Bootstrap-cfn uses `fabric <http://www.fabfile.org/>`_, so if your ``$CWD`` is the root directory of bootstrap-cfn then you can run::

    fab application:courtfinder aws:my_project_prod environment:dev config:/path/to/courtfinder-dev.yaml cfn_create


If your ``$CWD`` is anywhere else, you need to pass in a path to particular fabric file::

    fab -f /path/to/bootstrap-cfn/fabfile.py application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml cfn_create


- **application:courtfinder** - is just a name to associate with Cloudformation stack
- **aws:dev** - is a way to differentiate between AWS accounts ``(~/.config.yaml)``
- **environment:dev** - The ``dev`` section will be read from the projects YAML file (line 1 in the example below)
- **config:/path/to/file.yaml** - The location to the project YAML file

If you also want to bootstrap the salt master and minions, you can do this::

    fab application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml cfn_create install_master install_minions


Example Configuration
======================
AWS Account Configuration
++++++++++++++++++++++++++

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
+++++++++++++++++++++++++++
The `YAML file <https://github.com/ministryofjustice/bootstrap-cfn/blob/master/docs/sample-project.yaml>`_ highlights what is possible with all the bootstrap-cfn features available to date. The minimum requirement is that it must contain an *ec2* block, you **do not** have to use RDS, S3 or ELB's.



Salt specific configuration
++++++++++++++++++++++++++++

In order to rsync your salt states to the salt master you need to add a `salt` section to the top level of your project's YAML file. The following parameters specify the rsync sources and targets:

- **local_salt_dir**: Directory containing all the files you want to have in your salt root (for example top.sls or project specific states).
    **Default value**: ./salt
- **local_pillar_dir**: Directory containing all the files you want to have in your pillar root.
    **Default value**: ./pillar
- **local_vendor_dir**: Directory containing formulas cloned by salt-shaker.
    **Default value**: ./vendor
- **remote_state_dir**: Salt root on the master.
    **Default value**: /srv/salt
- **remote_pillar_dir**: Pillar root on the master.
    **Default value**: /srv/pillar

The cloudformation yaml will be automatically uploaded to your pillar as cloudformation.sls. So if you include ``-cloudformation`` in your pillar top file you can do things like:

::

    salt-call pillar.get s3:static-bucket-name

ELBs
++++++++++++++++++++
By default the ELBs will have a security group opening them to the world on 80 and 443. You can replace this default SG with your own (see example ``ELBSecGroup`` above).

If you set the protocol on an ELB to HTTPS you must include a key called `certificate_name` in the ELB block (as example above) and matching cert data in a key with the same name as the cert under `ssl` (see example above). The `cert` and `key` are required and the `chain` is optional.

The certificate will be uploaded before the stack is created and removed after it is deleted.

Applying a custom s3 policy
++++++++++++++++++++++++++++
You can add a custom s3 policy to override bootstrap-cfn's default settings. For example, the sample custom policy defined in this `json file <https://github.com/ministryofjustice/bootstrap-cfn/blob/master/tests/sample-custom-s3-policy.json>`_ can be configured as follows:

::

   s3:
     static-bucket-name: moj-test-dev-static
     policy: tests/sample-custom-s3-policy.json

Includes
++++++++++
If you wish to include some static cloudformation json and have it merged with the template generated by bootstrap-cfn. You can do the following in your template yaml file::

    includes:
      - /path/to/cloudformation.json

The tool will then merge this with the generated template *overwriting* any keys in the original template that clash.
