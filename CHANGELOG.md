## Version unreleased

 * Move timeout logic from fabric file into utility decorator.
 * Add wait_for_ssh function to the bootstrap commands. This ensures ssh is up before we bootstrap.
 * Rename fabfile to fab_tasks to make it easier to import in other projects.
 * Move bootstrap script execution to fabric tasks.
 * Fix bug in wait_for_ssh when no instances are running.

## Version 0.1

 * Build CloudFormation stack for a simple Web Application with a single ELB, EC2 instances and RDS

