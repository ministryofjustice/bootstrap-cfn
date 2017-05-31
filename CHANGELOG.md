## v1.5.0

Fixes:
* ELB records are put under 'hosted_zone' it defines in yaml
* Format R53 API calls -- contain zone_name in each call
* Fix 'get_deploy_arn' bug -- updated return:False to return:None

## v1.4.1

Fixes:
* Fix ACM alternative name tests
* Correct domain validation option for each host in subject alternative name
* Fix ACM certificate functionality.
* Parse ACM key into alphanumeric
* Add try catch on txt record deletion
* Fix unit tests on get_all_elbs
* Fix set_active_stack bug on internal LB

## v1.4.0

Features:
* Enable AWS Certificate Manager Support

Fixes:
* Make flake8 ignore parse errors in docs directory

## v1.3.0

Fixes:
* Drop awsencode use in tests

## v1.3.0rc1

Fixes:
* Disable production settings on staging
* Delete SSL certs only if defined in cf template
* Remove subnet hardwiring
* Add UK ami mappings
* Add a region argument to the aws task
* get elb helpers shouldn't raise if none elbs exist. (#238)
* Disable pretty printing of cfn template.
* Markup YAML fragments correctly
* Mark up bash commands correctly
* Show external references as a list
* Token delimitation
* Fix table
* Show the section headings correctly
* Exclude the yaml config files from flake8
* Update default RDS version to 9.5.4
* Make sure that set_active_stack activates all ELBs.
* Add version tag
* Added tests and updated README
* Update deployrarn when active stacks is changed

## v1.2.0

Fixes:
* change Elasticache instance size default to m1.medium

## v1.1.0

Features:
* Accept KeyName in fab parameters or config file

## v1.0.0

Initial release of version 1. This breaks backward compatibility due to the
addition of the multiple stacks feature.

# Features
* Add parallel stack support
* Add get_stack_list

# Fixes
* Rename S3 bucket output to be consistent

## v0.11.2

Fixes:
* flake8 import order fix 

## v0.11.1

Fixes:
* Upload data file properly into package

## v0.11.0

Features:
* Use a configuration file for default cloudformations settings

Fixes:
* Fixes cloudformation vpc dependency deletion issues
* Re-add elb permissions to ec2 host for aws-formula
* Adds missing permission of ELB `Describe*` on Resource `*` to
  ec2 iam policies.
* Default the dev RDS backup retention time to 1 day
* Only define policy actions if the components are enabled in the config

## v0.10.0

* Default RDS encryption to true

## v0.9.0

* Update Ubuntu AMI to 20160509.1 version ami-f9a62c8a

## v0.8.6

* Fixes exit_maintenance error
* add dry_run option to the maintenance tasks
* Add a test to check coverage levels
* Setup boto3 default session with default region

## v0.8.5

Fixes:
*Add MSSQL to EC2->RDS Security Group

## v0.8.4

Fixes: 
* Delete server certificates after we've replaced them
* Make update_certs task use set_ssl_certificates retry logic

## Version 0.8.3

Fixes:
* Stop attempting to set Name tag if its already manually set

## Version 0.8.2
 * Provide the ability to override the AMI used
 * Change to use the AWS Windows 2012 AMI

## Version 0.8.1

Features: 
* Add a Name tag to instances
* Allow the ASG config to use ELB healthchecks
* Update to latest Ubuntu 14.04 LTS AMI
* Add automatic upgrades to cloud-init.
* Add cycle instances task
Fixes:
* Add missing VPC class import to fab_tasks
* Set boto3 to use aws profile session

## Version 0.7.7

 * Add ability to create Windows 2012 machines

## Version 0.7.6

Fixes:
 * Fix update_certs fab task.
 
## Version 0.7.5

Fixes:
 * Fix settings stack_name in set_stack_name
 
## Version 0.7.4

Fixes:
 * Separate get and set_stack name
 * Remove the fallback when route53 stack name is missing
 * Add a function to return the basic config file with no AWS API calls

## Version 0.7.3

Fixes:
  * Restore the previous cloudformation_resource_type_for_back_compatibility
  
## Version 0.7.2

Fixes:
  * Fix back compatibility of cloudformation:get_resource_type

## Version 0.7.1

Fixes:
  * Fix certificate updating on live elbs

## Version 0.7.0

Fixes:
  * Add vpc peering
  * Add dynamic VPC address block subnetting
Features:
  * Fix autoscale get_all_groups paging

## Version 0.6.3

* Fix broken pypi release

## Version 0.6.2

* Bump version

## Version 0.6.1
Feature:
* Allow custom ELB policies

## Version 0.6.0

Features:
* Enable ec2 volume types
* Add multiple S3 buckets feature
* Added elasticache with engine redis

## Version 0.5.11

* Adds enter_maintenance and exit_maintenance fab tasks
* Adds support for updating route53 dns aliases

## Version 0.5.10

* Change AWS connection to use STS AssumeRole when AWS_ROLE_ARN_ID
environment variable is specified in addition to just the profile being
called "cross-account".

## Version 0.5.9

* Bump version

## Version 0.5.8

* Update the AWS AMI to the latest ubuntu, which includes the new kernel.
* Partially support sqlserver based RDS instances - which *cannot* have a
  DBName specified, so make that field not required for sqlserver backed
  instances.

## Version 0.5.7

* Provide hook point in cfn_delete fab task after confirm but before
  DeleteStack call.

  This is used by bootstrap-salt to remove a file that it places and manages
  in an S3 bucket so that the stack can be cleanly deleted.

* Let Cloudformation name the ELBs automatically to make creating multiple
  stacks easier.

  The 'name' parameter in each load balancer config is now only used to
  generate the DNS entries.

## Version 0.5.6

* Automaticly generate the RDS identifier

## Version 0.5.5

* Make it possible to override the ConfigParser so that sub-modules can update
  the CloudFormation config.
* Use a automatic resource naming to allow S3 bucket names to be auto named by
  AWS
* Added a new task `display_elb_dns_entries` to show the DNS name of each ELB
  in a stack

## Version 0.5.4

* Add an SSL cipher list policy pindown: implicitly (no YAML entry needed)
  or explicitly (with YAML entry)
* Allow security groups in YAML to reference themselves (for example an
  "elasticsearch" SG that allows other instances of that sg (and itself) to
  access port 9300)
* Add documentation to the `ec2` section
* Sort imports lines consistently and remove unused imports and some simple tests
* Generate Userdata script to set hostname of instances based on template
* Autoscale class that can find the scaling group based on a name

## Version 0.5.3

* Improve message content when cfn_create raises an exception and fails.
* Cleanup SSL certificates when cfn_create raises an exception and fails.
* Make default S3 permissions more restrictive. Everyone can get object.
* Deprecate the ec2.tags.Env tag and warn about its use

## Version 0.5.2

* Fix bug where certificates were not being deleted on calls to upload or
  delete due to a broken method call to get_remote_certificates

## Version 0.5.1

* Make it possible to create multiple stacks with the same app and env.

## Version 0.5.0

* Enable connection draining on ELBs
* Add IAM permissions so an instance can register/deregister itself from ELB.
* Add custom ELB healthchecks so you can point an ELB at a URL (not just a port)
* Replace internals with Troposphere - no more JSON loading and deep dict
  munging. This should be a transparent change to consumers of this module

## Version 0.4.1

* Fix dist to not include tests/ folder

  This would cause problems for downstream modules (i.e. bootstrap-salt) as
  they would then try to run our tests, but wouldn't have half the needed test
  modules.

## Version 0.4.0

First release to PyPi

## Version 0.3.3

* Add RDS encryption support

## Version 0.3.2

* Bump release version (broken release)

## Version 0.3.1

* Fixed the internal ELB bug
* Fixed the RDS storage-type bug

## Version 0.3.0

* Extract all the salt specific code into bootstrap-salt which lives in a
  seperate repo. We have tested this but it might break a few things for some
  projects. Sry **BREAKING CHANGE**

## Version 0.2.2

* Add include functionality for including extra cloudformation json files.
* Add ability to use cross account IAM roles when authenticating to AWS.

## Version 0.2.1

* Fix rsync missing passwords yaml from salt-pillar
* Make bootstrap process pull the bootstrap-cfn repo
* Document salt config variables.

## Version 0.2.0

 * Move timeout logic from fabric file into utility decorator.
 * Add wait_for_ssh function to the bootstrap commands. This ensures ssh is up before we bootstrap.
 * Rename fabfile to fab_tasks to make it easier to import in other projects.
 * Move bootstrap script execution to fabric tasks.
 * Fix bug in wait_for_ssh when no instances are running.
 * Add conditional statement in fabfile to check for ssl cert on roll back before trying to delete it.
 * Refactor fab_tasks get_config method to not return *every* config item. Also PEP8 fixes and removing unused functions.
 * Change security group input to dictionary so we can create multiple groups that reference each other.
 * Include cloudformation config in salt pillar.
 * Add SGs for ELBs and default open on 80/443

## Version 0.1

 * Build CloudFormation stack for a simple Web Application with a single ELB, EC2 instances and RDS

