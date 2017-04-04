import gzip

from StringIO import StringIO
from contextlib import closing
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


STARTS_WITH_MAPPINGS = {
    '#include': 'text/x-include-url',
    '#include-once': 'text/x-include-once-url',
    '#!': 'text/x-shellscript',
    '#cloud-config': 'text/cloud-config',
    '#cloud-config-archive': 'text/cloud-config-archive',
    '#upstart-job': 'text/upstart-job',
    '#part-handler': 'text/part-handler',
    '#cloud-boothook': 'text/cloud-boothook'
}


def try_decode(data):
    try:
        return (True, data.decode())
    except UnicodeDecodeError:
        return (False, data)


def get_type(content, deftype):
    rtype = deftype

    (can_be_decoded, content) = try_decode(content)

    if can_be_decoded:
        # slist is sorted longest first
        slist = sorted(list(STARTS_WITH_MAPPINGS.keys()), key=lambda e: 0 - len(e))
        for sstr in slist:
            if content.startswith(sstr):
                rtype = STARTS_WITH_MAPPINGS[sstr]
                break
    else:
        rtype = 'application/octet-stream'

    return(rtype)


def pack(parts, opts={}):
    outer = MIMEMultipart(boundary='boostrapcfnboundary141')

    for arg in parts:
        if isinstance(arg, basestring):
            arg = {'content': arg}

        if 'mime_type' in arg:
            mtype = arg['mime_type']
        else:
            mtype = get_type(arg['content'], opts.get('deftype', "text/plain"))

        maintype, subtype = mtype.split('/', 1)
        if maintype == 'text':
            # Note: we should handle calculating the charset
            msg = MIMEText(arg['content'], _subtype=subtype)
        else:
            msg = MIMEBase(maintype, subtype)
            msg.set_payload(arg['content'])
            # Encode the payload using Base64
            encoders.encode_base64(msg)

        outer.attach(msg)

    with closing(StringIO()) as buff:
        if opts.get('compress', False):
            gfile = gzip.GzipFile(fileobj=buff)
            gfile.write(outer.as_string().encode())
            gfile.close()
        else:
            buff.write(outer.as_string().encode())

        return buff.getvalue()
