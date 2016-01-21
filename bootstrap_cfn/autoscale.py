import boto.ec2.autoscale

from bootstrap_cfn import utils


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
            print "Created ASG Tag: Tag({0}, {1})".format(key, value)
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
