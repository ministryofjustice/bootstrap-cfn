class BootstrapCfnError(Exception):
    def __init__(self, msg):
        print "[ERROR] {0}: {1}".format(self.__class__.__name__, msg)

class CfnConfigError(BootstrapCfnError):
    pass
