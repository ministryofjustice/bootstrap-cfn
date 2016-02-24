import logging

import time

import boto.ec2.autoscale

import boto3

from bootstrap_cfn import utils

from bootstrap_cfn.errors import AutoscalingGroupNotFound, AutoscalingInstanceCountError


class Autoscale:

    def __init__(self, aws_profile_name, aws_region_name='eu-west-1'):
        self.group = None
        self.aws_profile_name = aws_profile_name
        self.aws_region_name = aws_region_name
        self.conn_asg = utils.connect_to_aws(boto.ec2.autoscale, self)

    def set_autoscaling_group(self, name):
        for grp in self.get_all_autoscaling_groups():
            for tag in grp.tags:
                if tag.key == 'aws:cloudformation:stack-name':
                    if str(tag.value) == str(name):
                        self.group = grp

    def set_tag(self, key, value):
        if self.group:
            tag = boto.ec2.autoscale.tag.Tag(
                self.conn_asg,
                key=key,
                value=value,
                resource_id=self.group.name)

            self.conn_asg.create_or_update_tags([tag])
            logging.getLogger("bootstrap-cfn").info("Created ASG Tag: Tag({0}, {1})"
                                                    .format(key, value))
            return True

    def get_all_autoscaling_groups(self):
        """
        Get all the auto-scaling groups in this connection
        Handle the pagination of results to make sure we get them all

        Returns:
            (list): A list of ASGs found
        """
        # Queries are paginated, while the results returned are truncated,
        # and we dont have a key_id, keep getting pages
        response = self.conn_asg.get_all_groups()
        all_asgs = response
        while response.next_token:
            response = self.conn_asg.get_all_groups(next_token=response.next_token)
            all_asgs += response
        return all_asgs

    def cycle_instances(self,
                        termination_delay=None):
        """
        Cycle all the instances in an autoscaling group, waiting for the
        specified delay before terminating each instance that was replaced

        Args:
            termination_delay(int): The delay in seconds between the new instance becoming
                healthy and in-service, and the termination of the old one its replacing.
        """
        client = boto3.client('autoscaling')

        # Use the type of health check the ASG is using to determine a sensible default for termination
        # delay. The ELB check is more nuanced and should know what a healthy service really looks like.
        # EC2 checks are basic and generally, the instance will be up and 'healthy' long before the service
        # is available. In that case we want to delay termination for a long enough time to hope the service
        # sets itself up.
        if not termination_delay and self.group.health_check_type != "ELB":
            termination_delay = 360

        # Get a list of the current instances
        current_instance_ids = [instance.get('InstanceId') for instance in self.get_healthy_instances()]
        logging.getLogger("bootstrap-cfn").info("cycle_instances: Found {} instance ids, {}"
                                                .format(len(current_instance_ids), current_instance_ids))

        # save the number of instances before starting the upgrade
        num_instances = len(current_instance_ids)

        # get the ASG HealthCheckGracePeriod
        health_check_grace_period = self.group.health_check_period
        logging.getLogger("bootstrap-cfn").info("ASG HealthCheckGracePeriod: %s" % health_check_grace_period)

        # Iterate through the current instances, replacing current instances with new ones
        for current_instance_id in current_instance_ids:
            logging.getLogger("bootstrap-cfn").info("current instance: %s" % current_instance_id)
            # Set the desired instances +1 and wait for it to be created

            logging.getLogger("bootstrap-cfn").info("cycle_instances: Creating new instance...")
            self.set_autoscaling_desired_capacity(len(current_instance_ids) + 1)
            self.wait_for_instances(len(current_instance_ids) + 1)
            logging.getLogger("bootstrap-cfn").info("cycle_instances: Terminating recycled instance {} after {} seconds..."
                                                    .format(current_instance_id, termination_delay))

            # wait for the same time as the "HealthCheckGracePeriod" in the ASG
            logging.getLogger("bootstrap-cfn").info("Waiting %ss - HealthCheckGracePeriod" % health_check_grace_period)
            time.sleep(health_check_grace_period)
            logging.getLogger("bootstrap-cfn").info("End of waiting period")

            # check if the number of healthy instances is = to the number of expected instances, where
            # expected instances is num_instances + 1
            new_curr_inst_ids = [instance.get('InstanceId') for instance in self.get_healthy_instances()]
            logging.getLogger("bootstrap-cfn").info("new instance list %r" % new_curr_inst_ids)
            if len(new_curr_inst_ids) != num_instances + 1:
                logging.getLogger("bootstrap-cfn").error("Expected %s instances, found %s." % (
                    num_instances + 1, len(new_curr_inst_ids))
                )
                raise AutoscalingInstanceCountError(self.group.name, num_instances + 1, new_curr_inst_ids)
            else:
                logging.getLogger("bootstrap-cfn").info("Expected %s instances, found %s." % (
                    num_instances + 1, len(new_curr_inst_ids))
                )

            # If we have a delay before termination defined, delay before terminating the current instance
            if termination_delay:
                logging.getLogger("bootstrap-cfn").info("Waiting %ss - termination_delay" % termination_delay)
                time.sleep(termination_delay)
                logging.getLogger("bootstrap-cfn").info("End of waiting period")
            client.terminate_instance_in_auto_scaling_group(
                InstanceId=current_instance_id,
                ShouldDecrementDesiredCapacity=True
            )
        new_instance_ids = [instance.get('InstanceId') for instance in self.get_healthy_instances()]
        logging.getLogger("bootstrap-cfn").info("cycle_instances: {} instances recycled, {}"
                                                .format(len(current_instance_ids), current_instance_ids))
        logging.getLogger("bootstrap-cfn").info("cycle_instances: {} instances created, {}"
                                                .format(len(new_instance_ids), new_instance_ids))

    def set_autoscaling_desired_capacity(self,
                                         capacity):
        """
        Set the desired instances count on an autosaling group

        Args:
            capacity(int): The target size of the instances in the
                autoscaling group.
        """
        client = boto3.client('autoscaling')
        logging.getLogger("bootstrap-cfn").info("set_autoscaling_desired_capacity: Setting capacity to {}".format(capacity))
        client.set_desired_capacity(
            AutoScalingGroupName=self.group.name,
            DesiredCapacity=capacity,
            HonorCooldown=False
        )

    def wait_for_instances(self,
                           expected_instance_count,
                           retry_delay=30,
                           retry_max=10):
        """
        Wait for the autoscaling group to register a specified number of healthy,
        in-service instances.

        Args:
            expected_instance_count(int): The target size of the instances in the
                autoscaling group.
            retry_delay(int): The time in seconds between checks on the number of
                instances.
            retry_max(int): The maximum number of retries on checking the instance
                count before failing.
        Exceptions:
            AutoscalingInstanceCountError: On target instance count not reached in
                retry_delay * retry_count time.
        """
        instances = self.get_healthy_instances()
        count = 0
        while (len(instances) != expected_instance_count and count < retry_max):
            count += 1
            logging.getLogger("bootstrap-cfn").info("cycle_instances: Waiting {} seconds for instances (attempt {}/{})..."
                                                    .format(retry_delay, count, retry_max))
            if count == retry_max:
                raise AutoscalingInstanceCountError(self.group.name, expected_instance_count, instances)
            time.sleep(retry_delay)
            instances = self.get_healthy_instances()
        logging.getLogger("bootstrap-cfn").info("wait_for_instances: Found {} instances, {}"
                                                .format(len(instances), [instance.get('InstanceId') for instance in instances]))

    def get_healthy_instances(self):
        instances = [instance for instance in self.get_instances()
                     if instance.get('LifecycleState') == 'InService' and
                     instance.get('HealthStatus') == 'Healthy']
        return instances

    def get_instances(self):
        """
        Get all instances in an autoscaling group
        """
        client = boto3.client('autoscaling')
        groups = client.describe_auto_scaling_groups(AutoScalingGroupNames=[self.group.name]).get('AutoScalingGroups')
        if not len(groups) > 0:
            logging.getLogger("bootstrap-cfn").critical("cycle_instances: Could not describe autoscaling group")
            raise AutoscalingGroupNotFound
        instances = [instance for instance in groups[0].get('Instances')]
        return instances
