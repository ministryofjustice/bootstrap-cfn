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

The test suite can be run via setup.py as follows:
::   
    python -m unittest discover
    
    or
    
    python setup.py test


Example Usage
==============

Bootstrap-cfn uses `fabric <http://www.fabfile.org/>`_, so if your ``$CWD`` is the root directory of bootstrap-cfn then you can run::

    fab application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml cfn_create


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

This tool can support many AWS accounts, for example, you may have separate *development* and *production* accounts, however you still want to deploy the same stack to each, this can be achieved by adding multiple accounts to the ``~/.config.yaml`` file. You'll notice from the **Example Usage** section above the ``aws:dev`` flag, this can be changed accordingly.

::

    provider_zones:
      dev:
        aws_access_key_id: 'AKIAI***********'
        aws_secret_access_key: '*******************************************'
      prod:
        aws_access_key_id: 'AKIAI***********'
        aws_secret_access_key: '*******************************************'


Project specific YAML file
+++++++++++++++++++++++++++
The YAML file below highlights what is possible with all the bootstrap-cfn features available to date. The minimum requirement is that it must contain an *ec2* block, you **do not** have to use RDS, S3 or ELB's.

::

    dev:
      ec2:
        auto_scaling:
          desired: 1
          max: 3
          min: 0
        tags:
          Role: docker
          Apps: test
          Env: dev
        parameters:
          KeyName: default
          InstanceType: t2.micro
        block_devices:
          - DeviceName: /dev/sda1
            VolumeSize: 10
          - DeviceName: /dev/sdf
            VolumeSize: 10
        security_groups:
          MySecGroup:
            - IpProtocol: tcp
              FromPort: 22
              ToPort: 22
              CidrIp: 0.0.0.0/0
            - IpProtocol: tcp
              FromPort: 80
              ToPort: 80
              CidrIp: 0.0.0.0/0
      elb:
        - name: test-dev-external
          hosted_zone: my.domain.com.
          scheme: internet-facing
          listeners:
            - LoadBalancerPort: 80
              InstancePort: 80
              Protocol: TCP
            - LoadBalancerPort: 443
              InstancePort: 443
              Protocol: TCP
        - name: test-dev-internal
          hosted_zone: my.domain.com.
          scheme: internet-facing
          security_groups:
            ELBSecGroup:
              - IpProtocol: tcp
                FromPort: 80
                ToPort: 80
                CidrIp: 10.0.0.0/0
          listeners:
            - LoadBalancerPort: 80
              InstancePort: 80
              Protocol: TCP
      s3:
        static-bucket-name: moj-test-dev-static
      rds:
        storage: 5
        storage-type: gp2
        backup-retention-period: 1
        identifier: test-dev
        db-name: test
        db-master-username: testuser
        db-master-password: testpassword
        instance-class: db.t2.micro
        multi-az: false
        db-engine: postgres
        db-engine-version: 9.3.5
      ssl:
        my-cert:
          cert: |
            -----BEGIN CERTIFICATE-----
            blahblahblah
            -----END CERTIFICATE-----
          key: |
            -----BEGIN RSA PRIVATE KEY-----
            blahblahblah
            -----END RSA PRIVATE KEY-----
          chain: |
            -----BEGIN CERTIFICATE-----
            blahblahblah
            -----END CERTIFICATE-----


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
