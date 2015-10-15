import boto.route53
import sys
from bootstrap_cfn import utils


class R53:


    conn_cfn = None
    aws_region_name = None
    aws_profile_name = None

    def __init__(self, aws_profile_name, aws_region_name='eu-west-1'):
        self.aws_profile_name = aws_profile_name
        self.aws_region_name = aws_region_name
        self.conn_r53 = utils.connect_to_aws('route53', self)

    def get_hosted_zone_id(self, zone_name):
        '''
        Take a zone name
        Return a zone id or None if no zone found
        Modified to use boto3
        '''
        zone = self.conn_r53.list_hosted_zones_by_name(DNSName=zone_name)
        if len(zone['HostedZones']) == 0:
            print "ERROR:get_hosted_zone_id:list_hosted_zones_by_name returns no values"
            # TODO: handle this exception appropriately
            return None
        print "DEBUG zone_name from R53: %s" % zone['HostedZones'][0]['Name']
        if zone['HostedZones'][0]['Name'] == zone_name + '.':
            # we found what we were looking for
            print "DEBUG FOUND %s Id: %s" % (zone_name, zone['HostedZones'][0]['Id'])
            print "DEBUG we are sending back %s" % zone['HostedZones'][0]['Id']
            return (zone['HostedZones'][0]['Id'])
        else:
            print "ERROR: zone %s not found in R53" % zone_name
            # TODO: handle this better
            return None

    def update_dns_record(self, zone, record, record_type, record_value):
        '''
        Returns True if update successful or raises an exception if not
        boto3 WIP 14/10/2015 working on this <<<======
        '''
        print "DEBUG inside update_dns_record"
        print "zone: " + str(zone)
        print "record: " + str(record)
        print "record_type: " + str(record_type)
        print "record_value: " + str(record_value)

        changes = self.conn_r53.change_resource_record_sets(
            HostedZoneId=zone,
            ChangeBatch={
                'Comment': 'some comment',
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': record,
                            'Type': record_type,
                            'TTL': 60,
                            'ResourceRecords': [
                                {
                                    'Value': record_value
                                },
                            ],
                        }
                    },
                ]
            }
        )

        #
        # changes = boto.route53.record.ResourceRecordSets(self.conn_r53, zone)
        # change = changes.add_change("UPSERT", record, record_type, ttl=60)
        # change.add_value(record_value)
        # changes.commit()
        return True
        
    def get_record(self, zone, zone_id, record, record_type):
        '''
        '''
        print "DEBUG: start r53 get_record"
        try:
            fqdn = "{0}.{1}.".format(record, zone)
            rrsets = self.conn_r53.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordName=fqdn,
                StartRecordType=record_type
            )
            if len(rrsets['ResourceRecordSets']) == 0:
                print "ERROR:get_record:list_resource_record_sets returns no values"
                # TODO: handle this exception appropriately
                return None
            # this is what we are after - if you don't like it, complain to Amazon!
            record_content = rrsets['ResourceRecordSets'][0]['ResourceRecords'][0]['Value']
            # we are not looping through the whole set because boto3 should point to the right one if found
            if rrsets['ResourceRecordSets'][0]['Name'] == fqdn and rrsets['ResourceRecordSets'][0]['Type'] == record_type:
                # we found what we were looking for
                # if the record they are after is TXT, let's strip double quotes
                if rrsets['ResourceRecordSets'][0]['Type'] == 'TXT':
                    record_content_stripped = record_content[1:-1]
                    record_content = record_content_stripped
                print "DEBUG: r53 get_record returning %r" % record_content
                return record_content
            else:
                print "ERROR: resource record sets not found for fqdn: %r and record type: %r" % (fqdn,record_type)
                # TODO: handle this better
                return None
        except:
            print "Unexpected error:", sys.exc_info()[0]
            sys.exit(1)