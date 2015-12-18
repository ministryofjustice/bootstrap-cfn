# VPC Configuration

----------------------------------------------------------------------

### Contents

##### [1. Basic configuration](#basic-configuration)

##### [2. Peering](#peering)

##### [A1. Examples](#examples)

* [Peered VPCs](#peered-vpcs)

--------------------------------------------------------------------------

### Basic configuration 

VPC configuration is done in the under the 'vpc' key section of the cloudformation configuration file.

Defaults are set so that without specifying anything, we get a VPC with CIDR `10.128.0.0/16` and 3 subnets, `10.128.0.0/20`, `10.128.16.0/20`, and `10.128.32.0/20`

We can alter this by specifying the CIDR and subnets specically, for example,

	vpc:
	    CIDR: 10.128.0.0/16
	    SubnetX: 10.128.0.0/20
	    SubnetY: 10.128.16.0/20


### Peering

Using the VPC class, we can setup up peering to another stacks VPC by calling `enable_vpc_peering`. This call will then

* Use the cloudformation configuration file to get a list of stacks to peer to
* Use the stack names to try and match to an existing stack, required since stack names have a random element
* Create a peering connection between the two stacks
* Add all or a specific set of routes between the two stacks.

Note that if security groups are needed, these are set up separately in the security_groups section of the cloudformation configuration file.

The configuration also understands wildcards, so the following configuration segments can be used to match a set of
route tables or cidr blocks.

We use the term 'source' to refer to the currently defined stack, and 'target' to refer to the stack we want to peer to. The peer stack does not need any additional vpc definition and is automatically set up using the source stacks configuration.


##### Add the target and source stacks VPC cidr blocks to all the route tables on a each stack
 
		vpc:
		    peering:
		      helloworld-dev1: '*'
		            
##### Add defined cidr blocks to all of the route tables on the source stack
 
		vpc:
		    peering:
		      helloworld-dev1:
		        source_routes:
		            '*':
		              cidr_blocks:
		                - 192.128.0.0/24
		                - 192.128.1.0/24
		       .....
		       
##### Add the target stacks full cidr block to the route table 'PublicRouteTable'
 
		vpc:
		    peering:
		      helloworld-dev1:
		        source_routes:
		            PublicRouteTable: "*"
		       .....
		       


### Examples

##### Peered VPCs

We can test out the stack below using the commands

	fab application:dev1 ... cfn_create
	fab application:dev2 ... cfn_create

Once both stacks have been created, we can then enable and disable peering by,

	fab application:dev1 ... enable_vpc_peering
	fab application:dev2 ... disable_vpc_peering

The cloudformation file,

	dev1:
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
	            Ref: DefaultSGhelloworlddev1
	      MySaltSG:
	        - IpProtocol: tcp
	          FromPort: 4505
	          ToPort: 4506
	          SourceSecurityGroupId:
	            Ref: MyBaseSG
	  elb:
	    - name: helloworld-dev1
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
	
	
	
	dev2:
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
	    - name: helloworld-dev2
	      hosted_zone: dsd.io.
	      scheme: internet-facing
	      listeners:
	        - LoadBalancerPort: 80
	          InstancePort: 80
	          Protocol: tcp
	  includes:
	    - ./cloudformation/iam-deploy.json
	 
