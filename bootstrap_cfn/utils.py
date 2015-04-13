import boto.exception
import boto.provider
import sys
import time

import bootstrap_cfn.errors as errors
from copy import deepcopy


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

def dict_merge(target, *args):
    # Merge multiple dicts
    if len(args) > 1:
        for obj in args:
            self.dict_merge(target, obj)
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
