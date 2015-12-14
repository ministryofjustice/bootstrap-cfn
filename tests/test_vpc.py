import unittest

from mock import patch

from testfixtures.comparison import compare

from bootstrap_cfn import vpc


class TestVPC(unittest.TestCase):

    @patch("bootstrap_cfn.vpc.VPC.get_vpc_route_table_ids")
    @patch("bootstrap_cfn.vpc.VPC.get_vpc_cidr_block")
    @patch("bootstrap_cfn.vpc.VPC.get_stack_vpc_id")
    @patch("bootstrap_cfn.vpc.VPC.get_stack_name_by_match")
    def test_init_stack_wildcard(self,
                                 mock_get_stack_name_by_match,
                                 mock_get_stack_vpc_id,
                                 mock_get_vpc_cidr_block,
                                 mock_get_vpc_route_table_ids):
        """
        TestVPC::test_init_stack_wildcard: Test that we generate the correct config when we have a wildcard on the entire stack
        """
        # Peer the fill stack cidr block between all routes
        config = {
            "vpc": {
                "peering": {
                    "peer_stack_1": "*"
                }
            }
        }

        mock_get_stack_name_by_match.return_value = [
            {"StackName": "peer_stack_1-abc"}
        ]
        mock_get_stack_vpc_id.side_effect = [
            "vpc_123",
            "peervpc_xyz"
        ]
        mock_get_vpc_cidr_block.side_effect = [
            "1.2.3.4/8",  # Self VPC cidr block
            "10.11.12.13/24"  # Peer VPC cidr block
        ]
        mock_get_vpc_route_table_ids.side_effect = [
            ["rt_abc", "rt_def"],  # All self vpc route tables
            ["rt_123", "rt_456", "rt_789"],  # All peering vpc route tables
            ["rt_abc", "rt_def"],  # All self vpc route tables
            ["rt_123", "rt_456", "rt_789"],  # All peering vpc route tables
            None
        ]

        stack_name = "test_stack"

        test_vpc = vpc.VPC(config, stack_name)

        expected_result = {
            "peer_stack_1":
            {
                "source_routes": {
                    "rt_abc": {
                        "cidr_blocks": ["1.2.3.4/8"],
                        "route_table_id": "rt_abc"
                    },
                    "rt_def": {
                        "cidr_blocks": ["1.2.3.4/8"],
                        "route_table_id": "rt_def"
                    }
                },
                "target_routes": {
                    "rt_123": {
                        "cidr_blocks": ["10.11.12.13/24"],
                        "route_table_id": "rt_123"
                    },
                    "rt_456": {
                        "cidr_blocks": ["10.11.12.13/24"],
                        "route_table_id": "rt_456"
                    },
                    "rt_789": {
                        "cidr_blocks": ["10.11.12.13/24"],
                        "route_table_id": "rt_789"
                    }
                },
                "vpc_id": "peervpc_xyz",
                "stack_name": "peer_stack_1-abc"
            }
        }
        actual_result = test_vpc.peering_config

        # Test our calling counts
        mock_get_stack_name_by_match.assert_called_with('peer_stack_1', min_results=1, max_results=1)
        mock_get_stack_vpc_id.assert_called_with('peer_stack_1-abc')
        # Getting the cidr block for self as its wildcarded
        mock_get_vpc_cidr_block.assert_called_with('peervpc_xyz')
        # Getting the route tables ids for one route on the peer only
        mock_get_vpc_route_table_ids.assert_called_with('peervpc_xyz')
        self.assertDictEqual(expected_result,
                             actual_result,
                             "TestVPC::test_init_stack_wildcard: "
                             "TODO: dicts not equal %s"
                             % (compare(expected_result, actual_result)))

    @patch("bootstrap_cfn.vpc.VPC.get_vpc_route_table_ids")
    @patch("bootstrap_cfn.vpc.VPC.get_vpc_cidr_block")
    @patch("bootstrap_cfn.vpc.VPC.get_stack_vpc_id")
    @patch("bootstrap_cfn.vpc.VPC.get_stack_name_by_match")
    def test_init_source_route_table_wildcard(self,
                                              mock_get_stack_name_by_match,
                                              mock_get_stack_vpc_id,
                                              mock_get_vpc_cidr_block,
                                              mock_get_vpc_route_table_ids):
        """
        TestVPC::test_init_source_route_table_wildcard: Test that we generate the correct config when we have a wildcard on the source routes
        """
        # Peer all source route tables to the full target stacks cidr block
        config = {
            "vpc": {
                "peering": {
                    "peer_stack_1": {
                        "source_routes": "*",
                        "target_routes": {
                            "rt_456": {
                                "cidr_blocks": ["66.66.66.66/24"]
                            }
                        }
                    }
                }
            }
        }

        mock_get_stack_name_by_match.return_value = [
            {"StackName": "peer_stack_1-abc"}
        ]
        mock_get_stack_vpc_id.side_effect = [
            "vpc_123",
            "peervpc_xyz"
        ]
        mock_get_vpc_cidr_block.side_effect = [
            "1.2.3.4/8",  # Self VPC cidr block
            "10.11.12.13/24"  # Peer VPC cidr block
        ]
        mock_get_vpc_route_table_ids.side_effect = [
            ["rt_abc", "rt_def"],  # All self vpc route tables
            ["rt_456"],  # Peering vpc route tables matched to rt_456
            ["rt_abc", "rt_def"],  # All self vpc route tables
            ["rt_456"],  # Peering vpc route tables matched to rt_456
            None
        ]

        stack_name = "test_stack"

        test_vpc = vpc.VPC(config, stack_name)

        expected_result = {
            "peer_stack_1":
            {
                "source_routes": {
                    "rt_abc": {
                        "cidr_blocks": ["1.2.3.4/8"],
                        "route_table_id": "rt_abc"
                    },
                    "rt_def": {
                        "cidr_blocks": ["1.2.3.4/8"],
                        "route_table_id": "rt_def"
                    }
                },
                "target_routes": {
                    "rt_456": {
                        "cidr_blocks": ["66.66.66.66/24"],
                        "route_table_id": "rt_456"
                    }
                },
                "vpc_id": "peervpc_xyz",
                "stack_name": "peer_stack_1-abc"
            }
        }
        actual_result = test_vpc.peering_config

        self.assertDictEqual(expected_result,
                             actual_result,
                             "TestVPC::test_init_source_route_table_wildcard: "
                             "TODO: dicts not equal %s"
                             % (compare(expected_result, actual_result)))

    @patch("bootstrap_cfn.vpc.VPC.get_vpc_route_table_ids")
    @patch("bootstrap_cfn.vpc.VPC.get_vpc_cidr_block")
    @patch("bootstrap_cfn.vpc.VPC.get_stack_vpc_id")
    @patch("bootstrap_cfn.vpc.VPC.get_stack_name_by_match")
    def test_init_target_route_table_wildcard(self,
                                              mock_get_stack_name_by_match,
                                              mock_get_stack_vpc_id,
                                              mock_get_vpc_cidr_block,
                                              mock_get_vpc_route_table_ids):
        """
         TestVPC::test_init_target_route_table_wildcard: Test that we generate the correct config when we have a wildcard on the target routes
        """
        # Peer all target route tables to the full source stacks cidr block
        config = {
            "vpc": {
                "peering": {
                    "peer_stack_1": {
                        "source_routes": {
                            "rt_def": {
                                "cidr_blocks": ["66.66.66.66/24"]
                            }
                        },
                        "target_routes": "*"
                    }
                }
            }
        }

        mock_get_stack_name_by_match.return_value = [
            {"StackName": "peer_stack_1-abc"}
        ]
        mock_get_stack_vpc_id.side_effect = [
            "vpc_123",
            "peervpc_xyz"
        ]
        mock_get_vpc_cidr_block.side_effect = [
            "1.2.3.4/8",  # Self VPC cidr block
        ]
        mock_get_vpc_route_table_ids.side_effect = [
            ["rt_def"],  # Self vpc route tables matched to rt_def
            ["rt_123", "rt_456", "rt_789"],  # All peering vpc route tables
            None
        ]

        stack_name = "test_stack"

        test_vpc = vpc.VPC(config, stack_name)

        expected_result = {
            "peer_stack_1":
            {
                "source_routes": {
                    "rt_def": {
                        "cidr_blocks": ["66.66.66.66/24"],
                        "route_table_id": "rt_def"
                    }
                },
                "target_routes": {
                    "rt_123": {
                        "cidr_blocks": ["1.2.3.4/8"],
                        "route_table_id": "rt_123"
                    },
                    "rt_456": {
                        "cidr_blocks": ["1.2.3.4/8"],
                        "route_table_id": "rt_456"
                    },
                    "rt_789": {
                        "cidr_blocks": ["1.2.3.4/8"],
                        "route_table_id": "rt_789"
                    }
                },
                "vpc_id": "peervpc_xyz",
                "stack_name": "peer_stack_1-abc"
            }
        }
        actual_result = test_vpc.peering_config

        self.assertDictEqual(expected_result,
                             actual_result,
                             "TestVPC::test_init_target_route_table_wildcard: "
                             "TODO: dicts not equal %s"
                             % (compare(expected_result, actual_result)))

    @patch("bootstrap_cfn.vpc.VPC.get_vpc_route_table_ids")
    @patch("bootstrap_cfn.vpc.VPC.get_vpc_cidr_block")
    @patch("bootstrap_cfn.vpc.VPC.get_stack_vpc_id")
    @patch("bootstrap_cfn.vpc.VPC.get_stack_name_by_match")
    def test_init_cidr_block_wildcards(self,
                                       mock_get_stack_name_by_match,
                                       mock_get_stack_vpc_id,
                                       mock_get_vpc_cidr_block,
                                       mock_get_vpc_route_table_ids):
        """
        TestVPC::test_init_cidr_block_wildcards: Test that we generate the correct config when we have a wildcard on the cidr blocks
        """
        mock_get_stack_name_by_match.return_value = [
            {"StackName": "peer_stack_1-abc"}
        ]
        mock_get_stack_vpc_id.side_effect = [
            "vpc_123",
            "peervpc_xyz"
        ]
        mock_get_vpc_cidr_block.side_effect = [
            "1.0.0.0/8",  # First Peer VPC cidr block
            "2.0.0.0/8",  # Self VPC cidr block
        ]
        mock_get_vpc_route_table_ids.side_effect = [
            ["rt_def"],
            ["rt_abc"],
            ["rt_456"],
            ["rt_123"],
            None
        ]
        # Peer all source/target cidr blocks to specific tables
        config = {
            "vpc": {
                "peering": {
                    "peer_stack_1": {
                        "source_routes": {
                            "rt_abc": {
                                "cidr_blocks": ["1.2.3.4/16", "5.6.7.8/16"],
                            },

                            "rt_def": {
                                "cidr_blocks": "*"
                            }
                        },
                        "target_routes": {
                            "rt_123": {
                                "cidr_blocks": ["2.2.3.4/16"],
                            },
                            "rt_456": {
                                "cidr_blocks": "*"
                            }
                        }
                    }
                }
            }
        }

        stack_name = "test_stack"

        test_vpc = vpc.VPC(config, stack_name)

        expected_result = {
            "peer_stack_1":
            {
                "source_routes": {
                    "rt_abc": {
                        "cidr_blocks": ["1.2.3.4/16", "5.6.7.8/16"],
                        "route_table_id": "rt_abc"
                    },
                    "rt_def": {
                        "cidr_blocks": ["1.0.0.0/8"],
                        "route_table_id": "rt_def"
                    }
                },
                "target_routes": {
                    "rt_123": {
                        "cidr_blocks": ["2.2.3.4/16"],
                        "route_table_id": "rt_123"
                    },
                    "rt_456": {
                        "cidr_blocks": ["2.0.0.0/8"],
                        "route_table_id": "rt_456"
                    }
                },
                "vpc_id": "peervpc_xyz",
                "stack_name": "peer_stack_1-abc"
            }
        }
        actual_result = test_vpc.peering_config

        self.assertDictEqual(expected_result,
                             actual_result,
                             "TestVPC::test_init_stack_wildcard: "
                             "TODO: dicts not equal %s"
                             % (compare(expected_result, actual_result)))
