import boto.exception
import boto.provider
import sys
import time

import bootstrap_cfn.errors as errors
from fabric.colors import green, red, yellow


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
        conn = module.connect_to_region(
            region_name=instance.aws_region_name,
            profile_name=instance.aws_profile_name
        )
        return conn
    except boto.exception.NoAuthHandlerFound:
        raise errors.NoCredentialsError()
    except boto.provider.ProfileNotFoundError as e:
        raise errors.ProfileNotFoundError(instance.aws_profile_name)


def tail(stack, stack_name):
    """Show and then tail the event log"""

    def colorize(e):
        if e.endswith("_IN_PROGRESS"):
            return yellow(e)
        elif e.endswith("_FAILED"):
            return red(e)
        elif e.endswith("_COMPLETE"):
            return green(e)
        else:
            return e

    def tail_print(e):
        print("%s %s %s" % (colorize(e.resource_status).ljust(30), e.resource_type.ljust(50), e.event_id))

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


