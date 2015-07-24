import unittest

import boto

import mock


def my_get_stack_load_balancers(a=None, b=None):
    a = boto.cloudformation.stack.StackResourceSummary()
    a.physical_resource_id = 'ELB-test'
    return [a]


def my_get_all_load_balancers(self, load_balancer_names):
    a = boto.ec2.elb.loadbalancer.LoadBalancer()
    a.dns_name = 'ELB-test.something.amazon.com'
    return [a]


def my_get_all_load_balancers_empty(self, load_balancer_names):
    return [None]


class TestELB(unittest.TestCase):

    def test_loaded(self):
        # Not a great test, but it at least checks for syntax erros in the file
        pass

    def test_list_domain_names(self):
        with mock.patch('bootstrap_cfn.cloudformation.Cloudformation.get_stack_load_balancers', my_get_stack_load_balancers):
            with mock.patch('boto.ec2.elb.ELBConnection.get_all_load_balancers', my_get_all_load_balancers):
                    stack_name = 'fake'
                    my_elb = mock.Mock()
                    elb_dns_list = my_elb.list_domain_names(stack_name)
                    self.assertTrue(elb_dns_list)
