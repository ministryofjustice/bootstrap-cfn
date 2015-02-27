# Ministry of Justice - Cloudformation

The objective of this repo is to enable MoJ teams to create project infrastructure in a uniform manner. Currently this includes the following AWS services:

  - EC2 Servers
  - Elastic Load Balancers (ELB)
  - Relational Database Service (RDS)
  - S3 Storage for web static content

## Installation

```sh
git clone git@github.com:ministryofjustice/bootstrap-cfn.git
cd bootstrap-cfn
pip install -r requirements.txt
```

## Developing and running tests

The test suite can be run via setup.py as follows

    python -m unittest discover

## Example Usage
Bootstrap-cfn uses [fabric](http://www.fabfile.org/), so if your ```$CWD``` is the root directory of bootstrap-cfn then you can run:

```
fab application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml cfn_create
```
To delete this stack, run:
```
fab application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml cfn_delete
```

If your ```CWD``` is anywhere else, you need to pass in a path to particular fabric file:

```
fab -f /path/to/bootstrap-cfn/fabfile.py application:courtfinder aws:prod environment:dev config:/path/to/courtfinder-dev.yaml cfn_create
```

* **application:courtfinder** - is just a name to associate with Cloudformation stack
* **aws:dev** - is a way to differentiate between AWS accounts (`~/.config.yaml`)
* **environment:dev** - The `dev` section will be read from the projects YAML file (line 1 in the example below)
* **config:/path/to/file.yaml** - The location to the project YAML file

## Example Configuration
##### AWS Account Configuration
This tool can support many AWS accounts, for example, you may have separate `development` and `production` accounts, however you still want to deploy the same stack to each, this can be achieved by adding multiple accounts to the `~/.config.yaml` file. You'll notice from the **Example Usage** section above the `aws:dev` flag, this can be changed accordingly.

```
provider_zones:
  dev:
    aws_access_key_id: 'AKIAI***********'
    aws_secret_access_key: '*******************************************'
  prod:
  	aws_access_key_id: 'AKIAI***********'
    aws_secret_access_key: '*******************************************'
```

##### Project specific YAML file
The YAML file below highlights what is possible with all the bootstrap-cfn features available to date. The minimum requirement is that it must contain an `ec2` block, you **do not** have to use RDS, S3 or ELB's.
```
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
```

