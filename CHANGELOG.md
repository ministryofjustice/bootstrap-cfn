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

