#!/usr/bin/env python

import os
import boto.ec2
import urllib2


# Example Tags
#
# Project: courtfinder
# Role: docker
# Apps: search,admin
# Env: dev

# GET REGION AND INSTANCE ID FROM METADATA API
instance_id = urllib2.urlopen('http://169.254.169.254/latest/meta-data/instance-id').read().strip()
region = urllib2.urlopen('http://169.254.169.254/latest/meta-data/placement/availability-zone').read().strip()[:-1]

# WRITE TAGS
conn = boto.ec2.connect_to_region(region)
instance = conn.get_all_instances(instance_ids=[instance_id])[0].instances[0]


tags = {'Project': '', 'Role': '', 'Apps': '', 'Env': ''}

for i in tags.keys():
    if i in instance.tags.keys():
        tags[i] = str(instance.tags[i])

# MAKE TAG DIRECTORY
tag_dir = '/etc/tags'
if os.path.isdir(tag_dir) is False:
    os.mkdir(tag_dir)

# WRITE TAGS TO DIRECTORY
for i in tags:
    f = open('%s/%s' % (tag_dir, i), 'w')
    print >> f, tags[i]
    f.close()
