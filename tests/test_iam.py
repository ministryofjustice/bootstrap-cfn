import unittest

import boto

from mock import Mock, patch

from nose.tools import raises

from bootstrap_cfn import iam
from bootstrap_cfn.errors import CloudResourceNotFoundError


class TestIAM(unittest.TestCase):

    # The IAM mock object to use
    mock_iam = None

    # Dictionary of test local cert data to use
    test_certs = \
        {
            "test_cert_1":
                {
                    "cert": ("-----BEGIN CERTIFICATE-----"
                             "CERT1CERT1CERT1CERT1CERT1CER"
                             "-----END CERTIFICATE-----"),
                    "chain": ("-----BEGIN CERTIFICATE-----"
                              "CHAIN1CHAIN1CHAIN1CHAIN1CHA"
                              "-----END CERTIFICATE-----"),
                    "key": ("-----BEGIN PRIVATE KEY-----"
                            "KEY1KEY1KEY1KEY1KEY1KEY1KEY"
                            "-----END PRIVATE KEY-----")
                },
            "test_cert_2":
                {
                    "cert": ("-----BEGIN CERTIFICATE-----"
                             "CERT2CERT2CERT2CERT2CERT2CER"
                             "-----END CERTIFICATE-----"),
                    "chain": ("-----BEGIN CERTIFICATE-----"
                              "CHAIN2CHAIN2CHAIN2CHAIN2CHA"
                              "-----END CERTIFICATE-----"),
                    "key": ("-----BEGIN PRIVATE KEY-----"
                            "KEY2KEY2KEY2KEY2KEY2KEY2KEY"
                            "-----END PRIVATE KEY-----")
                }
        }

    # Dictionary of test remote certificates to use
    remote_test_certs = \
        {
            "test_cert_1":
                {
                    "certificate_body": ("-----BEGIN CERTIFICATE-----"
                                         "CERT1CERT1CERT1CERT1CERT1CER"
                                         "-----END CERTIFICATE-----"),
                    "certificate_chain": ("-----BEGIN CERTIFICATE-----"
                                          "CHAIN1CHAIN1CHAIN1CHAIN1CHA"
                                          "-----END CERTIFICATE-----"),
                    "certificate_key": ("-----BEGIN PRIVATE KEY-----"
                                        "KEY1KEY1KEY1KEY1KEY1KEY1KEY"
                                        "-----END PRIVATE KEY-----")
                },
            "test_cert_3":
                {
                    "certificate_body": ("-----BEGIN CERTIFICATE-----"
                                         "CERT2CERT2CERT2CERT2CERT2CER"
                                         "-----END CERTIFICATE-----"),
                    "certificate_chain": ("-----BEGIN CERTIFICATE-----"
                                          "CHAIN2CHAIN2CHAIN2CHAIN2CHA"
                                          "-----END CERTIFICATE-----"),
                    "certificate_key": ("-----BEGIN PRIVATE KEY-----"
                                        "KEY2KEY2KEY2KEY2KEY2KEY2KEY"
                                        "-----END PRIVATE KEY-----")
                }
        }

    cert1_remote_get_certificate_response = \
        {
            "get_server_certificate_response":
            {
                "get_server_certificate_result":
                {
                    "server_certificate":
                    {
                        "certificate_body": ("-----BEGIN CERTIFICATE-----"
                                             "CERT1CERT1CERT1CERT1CERT1CER"
                                             "-----END CERTIFICATE-----"),
                        "certificate_chain": ("-----BEGIN CERTIFICATE-----"
                                              "CHAIN1CHAIN1CHAIN1CHAIN1CHA"
                                              "-----END CERTIFICATE-----"),
                        "certificate_key": ("-----BEGIN PRIVATE KEY-----"
                                            "KEY1KEY1KEY1KEY1KEY1KEY1KEY"
                                            "-----END PRIVATE KEY-----"),
                        }
                    }
                }
            }
    successful_response = \
        {
            "status": 200,
            "reason": "success",
            "body": ""
        }
    unsuccessful_response = \
        {
            "status": 404,
            "reason": "unsuccessful",
            "body": ""
        }

    def setUp(self):
        iam_mock = Mock()
        iam_connect_result = Mock(name='iam_connect')
        iam_mock.return_value = iam_connect_result
        boto.iam.connect_to_region = iam_mock
        self.mock_iam = iam.IAM('mock_profile')

    @patch("boto.iam.IAMConnection.upload_server_cert")
    @patch("bootstrap_cfn.iam.IAM.get_remote_certificate")
    def test_update_ssl_certificates(self,
                                     mock_get_remote_certificate,
                                     mock_upload_server_cert):
        """
        Test we update certificates when forced
        """
        mock_get_remote_certificate.side_effect = [self.remote_test_certs['test_cert_1'],
                                                   self.remote_test_certs['test_cert_3'],
                                                   None]
        mock_upload_server_cert.side_effect = [self.successful_response,
                                               self.successful_response]
        ssl_config = self.test_certs
        stack_name = "test_stack"

        update_list = self.mock_iam.update_ssl_certificates(ssl_config,
                                                            stack_name)
        self.assertEqual(len(update_list),
                         2,
                         "TestIAM::test_update_ssl_certificates_force: "
                         "Should be able update certs"
                         )

    @raises(CloudResourceNotFoundError)
    @patch("boto.iam.IAMConnection.delete_server_cert")
    @patch("boto.iam.IAMConnection.upload_server_cert")
    @patch("bootstrap_cfn.iam.IAM.get_remote_certificate")
    def test_update_ssl_certificates_not_exist(self,
                                               mock_get_remote_certificate,
                                               mock_upload_server_cert,
                                               mock_delete_server_cert):
        """
        Test we cause an exception trying update over
        non existing certificates
        """
        mock_get_remote_certificate.side_effect = [True,
                                                   False,
                                                   False,
                                                   None]
        mock_upload_server_cert.side_effect = [self.successful_response,
                                               self.unsuccessful_response,
                                               None]
        mock_delete_server_cert.side_effect = [self.successful_response,
                                               self.unsuccessful_response,
                                               None]
        ssl_config = self.test_certs
        stack_name = "test_stack"
        update_count = self.mock_iam.update_ssl_certificates(ssl_config,
                                                             stack_name)
        self.assertEqual(update_count,
                         1,
                         "TestIAM::test_update_ssl_certificates_force: "
                         "Should only be able to update existing certificates "
                         )

    @patch("boto.iam.IAMConnection.upload_server_cert")
    @patch("bootstrap_cfn.iam.IAM.get_remote_certificate")
    def test_upload_certificate_not_exists(self,
                                           mock_get_remote_certificate,
                                           mock_upload_server_cert):
        """
        Test that we can upload a certificate if it doesnt exist remotely
        """
        mock_get_remote_certificate.return_value = False
        mock_upload_server_cert.return_value = self.successful_response
        cert_name = "cert1"
        stack_name = "test_stack"
        ssl_data = self.test_certs["test_cert_1"]
        success = self.mock_iam.upload_certificate(cert_name,
                                                   stack_name,
                                                   ssl_data)
        mock_get_remote_certificate.assert_called_once_with(cert_name,
                                                            stack_name)
        self.assertTrue(success,
                        "TestIAM::test_upload_certificate_exists: "
                        "Should be able to upload a non existent cert "
                        )

    @patch("boto.iam.IAMConnection.upload_server_cert")
    @patch("bootstrap_cfn.iam.IAM.get_remote_certificate")
    def test_upload_certificate_exists(self,
                                       mock_get_remote_certificate,
                                       mock_upload_server_cert):
        """
        Test that we cannot upload a certificate if it exists remotely
        """
        mock_get_remote_certificate.return_value = True
        mock_upload_server_cert.return_value = self.unsuccessful_response
        cert_name = "cert1"
        stack_name = "test_stack"
        ssl_data = self.test_certs["test_cert_1"]
        success = self.mock_iam.upload_certificate(cert_name,
                                                   stack_name,
                                                   ssl_data)
        mock_get_remote_certificate.assert_called_once_with(cert_name,
                                                            stack_name)
        self.assertFalse(success,
                         "TestIAM::test_upload_certificate_exists: "
                         "Should not be able to upload an existent cert "
                         )

    @patch("boto.iam.IAMConnection.delete_server_cert")
    @patch("bootstrap_cfn.iam.IAM.get_remote_certificate")
    def test_delete_certificate_exists(self,
                                       mock_get_remote_certificate,
                                       mock_delete_server_cert):
        """
        Test that we can delete a certificate if it exists
        """
        mock_get_remote_certificate.return_value = True
        mock_delete_server_cert.return_value = self.successful_response
        cert_name = "cert1"
        stack_name = "test_stack"
        ssl_data = self.test_certs["test_cert_1"]

        success = self.mock_iam.delete_certificate(cert_name,
                                                   stack_name,
                                                   ssl_data)
        mock_get_remote_certificate.assert_called_once_with(cert_name,
                                                            stack_name)
        self.assertTrue(success,
                        "TestIAM::test_delete_certificate_exists: "
                        "Should only be able to delete an existent cert "
                        )

    @patch("boto.iam.IAMConnection.delete_server_cert")
    @patch("bootstrap_cfn.iam.IAM.get_remote_certificate")
    def test_delete_certificate_not_exists(self,
                                           mock_get_remote_certificate,
                                           mock_delete_server_cert):
        """
        Test we get false on trying to delete a non-existent certificate
        """
        mock_get_remote_certificate.return_value = None
        mock_delete_server_cert.return_value = self.unsuccessful_response
        cert_name = "cert1"
        stack_name = "test_stack"
        ssl_data = self.test_certs["test_cert_1"]

        success = self.mock_iam.delete_certificate(cert_name,
                                                   stack_name,
                                                   ssl_data)
        mock_get_remote_certificate.assert_called_once_with(cert_name,
                                                            stack_name)
        self.assertFalse(success,
                         "TestIAM::test_delete_certificate_not_exists: "
                         "Should not be able to delete "
                         "a non-existant cert")

    def test_compare_certificates_equal(self):
        local_cert_data = self.test_certs["test_cert_1"]
        remote_cert = self.remote_test_certs["test_cert_1"]
        remote_cert_data = \
            {
                "cert": remote_cert["certificate_body"],
                "chain": remote_cert["certificate_chain"],
                "key": remote_cert["certificate_key"],
            }
        certs_equal = self.mock_iam.compare_certificate_data(local_cert_data,
                                                             remote_cert_data)

        self.assertTrue(certs_equal,
                        "Local and remote certificates should be equal")

    def test_compare_certificates_unequal(self):
        local_cert_data = self.test_certs["test_cert_1"]
        remote_cert1 = self.remote_test_certs["test_cert_1"]
        remote_cert2 = self.remote_test_certs["test_cert_3"]

        # Test when cert is different
        remote_cert_data = \
            {
                "cert": remote_cert2["certificate_body"],
                "chain": remote_cert1["certificate_chain"],
            }
        certs_equal = self.mock_iam.compare_certificate_data(local_cert_data,
                                                             remote_cert_data)

        self.assertFalse(certs_equal,
                         "Local and remote certificates should not be equal"
                         )

        # Test when chain is different
        remote_cert_data = \
            {
                "cert": remote_cert1["certificate_body"],
                "chain": remote_cert2["certificate_chain"],
            }
        certs_equal = self.mock_iam.compare_certificate_data(local_cert_data,
                                                             remote_cert_data)

        self.assertFalse(certs_equal,
                         "Local and remote certificates should not be equal"
                         )
