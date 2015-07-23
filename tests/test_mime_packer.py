import email

import unittest

from testfixtures import compare

from bootstrap_cfn import mime_packer


class TestMimePacker(unittest.TestCase):

    def setUp(self):
        self.parts = []
        self.parts.append({
            'content': 'MORESTRING',
            'mime_type': 'text/cloud-boothook'
        })
        self.parts.append({
            'content': 'SOMESTRING',
            'mime_type': 'text/cloud-config'
        })

    def test_encode(self):
        ret = mime_packer.pack(self.parts)
        self.assertTrue('SOMESTRING' in ret)
        self.assertTrue('MORESTRING' in ret)

    def test_decode(self):
        ret = mime_packer.pack(self.parts)
        parts = [part for part in email.message_from_string(ret).walk()]
        compare(
            [part.get_content_type() for part in parts],
            ["multipart/mixed", "text/cloud-boothook", "text/cloud-config"],
            prefix="mimeparts are in expected order")
        compare(parts[1].get_payload(), "MORESTRING")
        compare(parts[2].get_payload(), "SOMESTRING")
