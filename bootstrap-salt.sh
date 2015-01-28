#!/bin/bash -xe

# SETUP EC2 INSTANCE
apt-get update
apt-get -y install python-setuptools git

easy_install https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz

wget https://raw.githubusercontent.com/saltstack/salt-bootstrap/6080a18e6c7c2d49335978fa69fa63645b45bc2a/bootstrap-salt.sh -O /tmp/bootstrap-salt.sh
chmod 755 /tmp/bootstrap-salt.sh
/tmp/bootstrap-salt.sh -X git v2014.1.4
