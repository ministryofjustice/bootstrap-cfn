import boto.route53

from bootstrap_cfn import utils


class R53(object):

    # ELB zone ids, these are default for AWS
    # (and may need updating if AWS changes them)
    AWS_ELB_ZONE_ID = {
        "ap-northeast-1": "Z2YN17T5R711GT",
        "ap-southeast-1": "Z1WI8VXHPB1R38",
        "ap-southeast-2": "Z2999QAZ9SRTIC",
        "eu-west-1": "Z3NF1Z3NOM5OY2",
        "eu-central-1": "Z215JYRZR1TBD5",
        "sa-east-1": "Z2ES78Y61JGQKS",
        "us-east-1": "Z3DZXE0Q79N41H",
        "us-west-1": "Z1M58G0W56PQJA",
        "us-west-2": "Z33MTJ483KN6FU"
    }

    conn_cfn = None
    aws_region_name = None
    aws_profile_name = None

    def __init__(self, aws_profile_name, aws_region_name='eu-west-1'):
        self.aws_profile_name = aws_profile_name
        self.aws_region_name = aws_region_name

        self.conn_r53 = utils.connect_to_aws(boto.route53, self)

    def get_hosted_zone_id(self, zone_name):
        '''
        Take a zone name
        Return a zone id or None if no zone found
        '''
        zone = self.conn_r53.get_hosted_zone_by_name(zone_name)
        if zone:
            zone = zone['GetHostedZoneResponse']['HostedZone']['Id']
            return zone.replace('/hostedzone/', '')

    def update_dns_record(self, zone, record, record_type, record_value, is_alias=False, dry_run=False):
        '''
        Updates a dns record in route53

        zone -- a string specifying the zone id
        record -- a string for the record to update
        record_value -- a string if it is not an alias
                        a list, if it is an alias, of parameters to pass to
                        boto record.set_alias() function
        is_alias -- a boolean to show if record_value is an alias
        record_type -- a string to specify the record, eg "A"


        Returns True if update successful or raises an exception if not
        '''
        changes = boto.route53.record.ResourceRecordSets(self.conn_r53, zone)
        change = changes.add_change("UPSERT", record, record_type, ttl=60)
        if is_alias:
            # provide list of params as needed by function set_alias
            # http://boto.readthedocs.org/en/latest/ref/route53.html#boto.route53.record.Record.set_alias
            alias_hosted_zone_id = record_value.alias_hosted_zone_id
            alias_dns_name = record_value.alias_dns_name
            alias_evaluate_target_health = record_value.alias_evaluate_target_health
            change.set_alias(alias_hosted_zone_id, alias_dns_name, alias_evaluate_target_health)
        else:
            change.add_value(record_value)
        if dry_run:
            print(changes)
        else:
            changes.commit()
        return True

    def delete_dns_record(self, zone, record, record_type, record_value, is_alias=False, dry_run=False):
        '''
        Delete a dns record in route53

        zone -- a string specifying the zone id
        record -- a string for the record to update
        record_type -- a string to specify the record, eg "A"


        Returns True if update successful or raises an exception if not
        '''
        changes = boto.route53.record.ResourceRecordSets(self.conn_r53, zone)
        change = changes.add_change("DELETE", record, record_type, ttl=60)
        if is_alias:
            # provide list of params as needed by function set_alias
            # http://boto.readthedocs.org/en/latest/ref/route53.html#boto.route53.record.Record.set_alias
            alias_hosted_zone_id = record_value.alias_hosted_zone_id
            alias_dns_name = record_value.alias_dns_name
            alias_evaluate_target_health = record_value.alias_evaluate_target_health
            change.set_alias(alias_hosted_zone_id, alias_dns_name, alias_evaluate_target_health)
        else:
            change.add_value(record_value)
        if dry_run:
            print(changes)
        else:
            res = changes.commit()
        return res

    def get_record(self, zone, zone_id, record, record_type):
        '''
        '''
        fqdn = "{0}.{1}.".format(record, zone)
        rrsets = self.conn_r53.get_all_rrsets(zone_id, type=record_type, name=fqdn)
        for rr in rrsets:
            if rr.type == record_type and rr.name == fqdn:
                if rr.type == 'TXT':
                    rr.resource_records[0] = rr.resource_records[0][1:-1]
                if rr.type == 'A':
                    return rr
                return rr.resource_records[0]
        return None
