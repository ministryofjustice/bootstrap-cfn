# VPC Configuration

### Contents

##### [1. Basic configuration](#basic-configuration)

VPC configuration is done in the under the 'vpc' key section of the cloudformation configuration file.

Defaults are set so that without specifying anything, we get a VPC with CIDR `10.128.0.0/16` and 3 subnets, `10.0.0.0/20`, `10.0.16.0/20`, and `10.0.32.0/20`

We can alter this by specifying the CIDR and subnets specically, for example,

	vpc:
	    CIDR: 10.128.0.0/16
	    SubnetX: 10.128.0.0/20
	    SubnetY: 10.128.16.0/20

##### [2. Peering](#peering)

##### [A1. Examples](#examples)

* [Peered VPCs](#peered-vpcs)

### Basic configuration 


### Peering

Using the VPC class, we can setup up peering to another VPC by calling enable_peering. This call will then

* Use the cloudformation configuration file to get a list of stacks to peer to
* Use the stack names to try and match to an existing stack, required since stack names have a random element
* Create a peering connection between the two stacks
* Add routes between the two stacks to each others default route table

Note that if security groups are needed, these are set up separately in the security_groups section of the cloudformation configuration file.

##### Setting peering stacks

##### Set the security groups

### Examples

##### Peered VPCs

	dev:
	  vpc:
	    CIDR: 10.128.0.0/16
	    SubnetA: 10.128.0.0/20
	    SubnetB: 10.128.16.0/20
	    SubnetC: 10.128.32.0/20
	    peering:
	      # Peer to the stack name helloworld-dev1 with no additional configuration
	      helloworld-dev1: {}
	  master_zone: dsd.io
	  ec2:
	    auto_scaling:
	      desired: 1
	      max: 2
	      min: 0
	    tags:
	      Role: docker
	      Apps: helloworld
	    parameters:
	      KeyName: default
	      InstanceType: t2.micro
	    block_devices:
	      - DeviceName: /dev/sda1
	        VolumeSize: 10
	    security_groups:
	      MyBaseSG:
	        - IpProtocol: tcp
	          FromPort: 22
	          ToPort: 22
	          # The CIDR range of the peering VPC
	          CidrIp: 10.0.0.0/16
	        - IpProtocol: tcp
	          FromPort: 22
	          ToPort: 22
	          # This is the ext IP on the MoJD network so that we can ssh.
	          CidrIp: 81.134.202.29/32
	      WebServer:
	        - IpProtocol: tcp
	          FromPort: 80
	          ToPort: 80
	          SourceSecurityGroupId:
	            Ref: DefaultSGhelloworlddev
	      MySaltSG:
	        - IpProtocol: tcp
	          FromPort: 4505
	          ToPort: 4506
	          SourceSecurityGroupId:
	            Ref: MyBaseSG
	  elb:
	    - name: helloworld-dev
	      # This zone must exist in the AWS account you are using.
	      hosted_zone: dsd.io.
	      scheme: internet-facing
	      listeners:
	        - LoadBalancerPort: 80
	          InstancePort: 80
	          Protocol: tcp
	  includes:
	    - ./cloudformation/iam-deploy.json
	  s3: {}
	
	
	
	dev1:
	  master_zone: dsd.io
	  ec2:
	    auto_scaling:
	      desired: 1
	      max: 2
	      min: 0
	    tags:
	      Role: docker
	      Apps: helloworld
	    parameters:
	      KeyName: default
	      InstanceType: t2.micro
	    block_devices:
	      - DeviceName: /dev/sda1
	        VolumeSize: 10
	    security_groups:
	      MyBaseSG:
	        - IpProtocol: tcp
	          FromPort: 22
	          ToPort: 22
	          # The CIDR range of the peering VPC
	          CidrIp: 10.128.0.0/16
	        - IpProtocol: tcp
	          FromPort: 22
	          ToPort: 22
	          # This is the ext IP on the MoJD network so that we can ssh.
	          CidrIp: 81.134.202.29/32
	      WebServer:
	        - IpProtocol: tcp
	          FromPort: 80
	          ToPort: 80
	          SourceSecurityGroupId:
	            Ref: DefaultSGhelloworlddev1
	      MySaltSG:
	        - IpProtocol: tcp
	          FromPort: 4505
	          ToPort: 4506
	          SourceSecurityGroupId:
	            Ref: MyBaseSG
	  elb:
	    - name: helloworld-dev1
	      hosted_zone: dsd.io.
	      scheme: internet-facing
	      listeners:
	        - LoadBalancerPort: 80
	          InstancePort: 80
	          Protocol: tcp
	  includes:
	    - ./cloudformation/iam-deploy.json
	 