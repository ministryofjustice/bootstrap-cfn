import logging
import difflib

from fabric.colors import green, red


def diff(src, tgt, prefix=None, changes=None):
    t_src = type(src)
    t_dst = type(tgt)

    if prefix is None:
        logging.info("---------------- CFN DIFF FOLLOWS ----------------")
        new_prefix = "root"
    else:
        new_prefix = prefix

    if changes is None:
        changes = []

    if t_src != t_dst:
        logging.info("src is {t1} while dst is {t2}".format(t1=t_src, t2=t_dst))
        return False

    if t_src is dict and t_dst is dict:
        rc = diffdict(src, tgt, new_prefix, changes=changes)
        if rc:
            changes.append(rc)

    if t_src in [str, unicode, int] and t_dst in [str, unicode, int]:
        rc = diffstr(src, tgt, new_prefix, changes=changes)
        if rc:
            changes.append(rc)

    if prefix is None:
        logging.info("---------------- CFN DIFF ENDS ----------------")

    return changes


def diffstr(src, tgt, prefix, changes):
    if src != tgt:
        if 'Properties.UserData.Fn::Base64' not in prefix:
            logging.info("{0}: CHANGED from {1} to {2}".format(prefix, red(src), green(tgt)))
        else:
            all_lines = ''
            logging.info("{0}: Launch configuration diff starts".format(prefix))
            for i in difflib.unified_diff(src.splitlines(1),
                                          tgt.splitlines(1),
                                          fromfile='old launch configuration',
                                          tofile='new launch configuration'):
                all_lines = all_lines + i
            logging.info("\n{}".format(all_lines))
            logging.info("{0}: LaunchConfiguration diff ends. File is changing. Please be careful".format(prefix))
        changes = {"key": prefix, "old": src, "new": tgt}
    else:
        changes = None
    return changes


def diffdict(src, tgt, prefix=None, changes=[]):
    #
    # We delete the Metadata key added by Cloudformation when a
    # template has been edited in the editor
    #
    try:
        del src['Metadata']
        del tgt['Metadata']
    except:
        pass

    s_src = set(src)
    s_tgt = set(tgt)

    #
    # keys only in src
    #
    only_src = s_src - s_tgt
    if only_src != set():
        logging.info("{0}: REMOVED keys from target: {1}".format(prefix, red(only_src)))

    #
    # keys only in dst
    #
    only_tgt = s_tgt - s_src
    if only_tgt != set():
        logging.info("{0}: ADDED keys to target: {1}".format(prefix, green(only_tgt)))

    if only_tgt != set() or only_src != set():
        changes.append({"key": prefix, "removed": only_src, "added": only_tgt})
    #
    # Recurse on common keys
    #
    common = s_src.intersection(s_tgt)
    for i in common:
        diff(src[i], tgt[i],  prefix="{0}.{1}".format(prefix, i), changes=changes)
