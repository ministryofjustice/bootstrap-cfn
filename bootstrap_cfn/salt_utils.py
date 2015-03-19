#!/usr/bin/env python
from bootstrap_cfn import utils
from bootstrap_cfn import errors
import salt
import salt.runner
import salt.client
import pprint
import time
import sys

def start_highstate(target):
    local = salt.client.LocalClient()
    jid = local.cmd_async(target, 'state.highstate')
    return jid

def start_state(target, state):
    local = salt.client.LocalClient()
    jid = local.cmd_async(target, 'state.sls', [state])
    return jid

def state_result(jid):
    opts = salt.config.master_config('/etc/salt/master')
    r = salt.runner.RunnerClient(opts)
    result = r.cmd('jobs.lookup_jid', [jid])
    if result:
        return result
    return False

def highstate(target, timeout, interval):
    jid = start_highstate(target)
    res = utils.timeout(timeout, interval)(state_result)(jid)
    return check_state_result(res)

def state(target, state, timeout, interval):
    jid = start_state(target, state)
    res = utils.timeout(timeout, interval)(state_result)(jid)
    return check_state_result(res)

def check_state_result(result):
    results = []
    for ret in result.values():
        if isinstance(ret, dict):
            results += [v['result'] for v in ret.values()]
        else:
            raise errors.SaltParserError('Minion could not parse state data')
    if all(results):
        return True
    else:
        raise errors.SaltStateError('State did not execute successfully')

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Run salt states')
    parser.add_argument('-t', dest='target', type=str,
                       help='target', required=True)
    parser.add_argument('-s', dest='state', type=str,
                       help='Name of state or "highstate"', required=True)
    parser.add_argument('-T', dest='timeout', type=float,
                       help='Timeout to wait for state execution to finish'\
                            'on all minions.', required=False, default = 1800)
    parser.add_argument('-I', dest='interval', type=float,
                       help='Interval to check for finished execution.',
                       required=False, default=10)
                            
    args = parser.parse_args()
    if args.state == "highstate":
        highstate(args.target, args.timeout, args.interval)
    else:
        state(args.target, args.state, args.timeout, args.interval)
