import boto.route53
import utils


class R53:

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

    def update_dns_record(self, zone, record, record_type, record_value):
        '''
        Returns True if update successful or raises an exception if not
        '''
        changes = boto.route53.record.ResourceRecordSets(self.conn_r53, zone)
        change = changes.add_change("UPSERT", record, record_type, ttl=60)
        change.add_value(record_value)
        changes.commit()
        return True

    def get_record(self, zone, zone_id, record, record_type):
        '''
        '''
        fqdn = "{0}.{1}.".format(record, zone)
        rrsets = self.conn_r53.get_all_rrsets(zone_id, type=record_type, name=fqdn)
        for rr in rrsets:
            if rr.type == record_type and rr.name == fqdn:
                if rr.type == 'TXT':
                    rr.resource_records[0] = rr.resource_records[0][1:-1]
                return rr.resource_records[0]
        return None
