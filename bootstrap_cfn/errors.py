import sys

class BootstrapCfnError(Exception):
    def __init__(self, msg):
        print >> sys.stderr,  "[ERROR] {0}: {1}".format(self.__class__.__name__, msg)

class CfnConfigError(BootstrapCfnError):
    pass

class CfnTimeoutError(BootstrapCfnError):
    pass

class NoCredentialsError(BootstrapCfnError):
    def __init__(self):
        super(NoCredentialsErrror, self).__init__(
            "Create an ~/.aws/credentials file by following this layout:\n\n" +
            "  http://boto.readthedocs.org/en/latest/boto_config_tut.html#credentials"
        )

class ProfileNotFoundError(BootstrapCfnError):
    def __init__(self, profile_name):
        super(ProfileNotFoundError, self).__init__(
            "'{0}' not found in ~/.aws/credentials".format(profile_name)
        )

class SaltStateError(BootstrapCfnError):
    pass

class SaltParserError(BootstrapCfnError):
    pass
