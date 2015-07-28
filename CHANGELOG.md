## Version 0.5.6
* Automaticly generate the RDS identifier

## Version 0.5.5
* Make it possible to override the ConfigParser so that sub-modules can update the CloudFormation config.
* Use a automatic resource naming to allow S3 bucket names to be auto named by AWS
* Added a new task `display_elb_dns_entries` to show the DNS name of each ELB in a stack

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

