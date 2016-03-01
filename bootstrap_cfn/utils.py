import os
import sys
import time

from copy import deepcopy

import boto.exception
import boto.provider
import boto.sts

import bootstrap_cfn.errors as errors


def timeout(timeout, interval):
    def decorate(func):
        def wrapper(*args, **kwargs):
            attempts = 0
            while True:
                result = func(*args, **kwargs)
                if result:
                    return result
                if attempts >= timeout / interval:
                    raise errors.CfnTimeoutError("Timeout in {0}".format(func.__name__))
                attempts += 1
                time.sleep(interval)
        return wrapper
    return decorate


def connect_to_aws(module, instance):
    try:
        # Check if we have a AWS_ROLE_ARN_ID set, if so we will attempt
        # to assume a role and connect no matter whether we're on the
        # cross-account profile or not.
        if (instance.aws_profile_name == 'cross-account' or
                os.environ.get('AWS_ROLE_ARN_ID', False)):
            sts = boto.sts.connect_to_region(
                region_name=instance.aws_region_name,
                profile_name=instance.aws_profile_name
            )
            role = sts.assume_role(
                role_arn=os.environ['AWS_ROLE_ARN_ID'],
                role_session_name="AssumeRoleSession1"
            )
            conn = module.connect_to_region(
                region_name=instance.aws_region_name,
                aws_access_key_id=role.credentials.access_key,
                aws_secret_access_key=role.credentials.secret_key,
                security_token=role.credentials.session_token
            )
            return conn
        conn = module.connect_to_region(
            region_name=instance.aws_region_name,
            profile_name=instance.aws_profile_name
        )
        return conn
    except boto.exception.NoAuthHandlerFound:
        raise errors.NoCredentialsError()
    except boto.provider.ProfileNotFoundError as e:
        raise errors.ProfileNotFoundError(instance.aws_profile_name)


def dict_merge(target, *args):
    # Merge multiple dicts
    if len(args) > 1:
        for obj in args:
            dict_merge(target, obj)
        return target

    # Recursively merge dicts and set non-dict values
    obj = args[0]
    if not isinstance(obj, dict):
        return obj
    for k, v in obj.iteritems():
        if k in target and isinstance(target[k], dict):
            dict_merge(target[k], v)
        else:
            target[k] = deepcopy(v)
    return target


def tail(stack, stack_name):
    from fabric.colors import green, red, yellow
    """Show and then tail the event log"""

    def colorize(e):
        if e.endswith("_IN_PROGRESS"):
            return yellow(e)
        elif e.endswith("_FAILED") or e.startswith("ROLLBACK"):
            return red(e)
        elif e.endswith("_COMPLETE"):
            return green(e)
        else:
            return e

    def tail_print(e):
        print("%s %s %s" % (colorize(e.resource_status).ljust(30), e.resource_type.ljust(50), e.event_id))
        if e.resource_status_reason:
            print(e.resource_status_reason)

    # First dump the full list of events in chronological order and keep
    # track of the events we've seen already
    seen = set()
    initial_events = get_events(stack, stack_name)
    for e in initial_events:
        tail_print(e)
        seen.add(e.event_id)

    # Now keep looping through and dump the new events
    while 1:
        if stack.stack_missing(stack_name):
            break
        elif stack.stack_done(stack_name):
            break
        events = get_events(stack, stack_name)
        for e in events:
            if e.event_id not in seen:
                tail_print(e)
            seen.add(e.event_id)
        time.sleep(2)


def get_events(stack, stack_name):
    """Get the events in batches and return in chronological order"""
    next = None
    event_list = []
    while 1 and not stack.stack_missing(stack_name):
        try:
            events = stack.conn_cfn.describe_stack_events(stack_name, next)
        except:
            break
        event_list.append(events)
        if events.next_token is None:
            break
        next = events.next_token
        time.sleep(1)
    return reversed(sum(event_list, []))


def sleep_countdown(sleep_time):
    """
    Simple terminal countdown of the form mm:ss

    Args:
        sleep_time(int): The number of seconds to countdown from.
    """
    while sleep_time > 0:
        mins, secs = divmod(sleep_time, 60)
        timeformat = '{:02d}:{:02d}'.format(mins, secs)
        sys.stdout.write("{}\r".format(timeformat))
        sys.stdout.flush()
        time.sleep(1)
        sleep_time -= 1
