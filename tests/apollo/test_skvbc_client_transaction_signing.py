# Concord
#
# Copyright (c) 2021 VMware, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache 2.0 license (the "License").
# You may not use this product except in compliance with the Apache 2.0 License.
#
# This product may include a number of subcomponents with separate copyright
# notices and license terms. Your use of these subcomponents is subject to the
# terms and conditions of the subcomponent's license, as noted in the LICENSE
# file.

import os.path
import random
import unittest
from os import environ

import trio

#from util import blinking_replica
from util import skvbc as kvbc
from util.bft import with_trio, with_bft_network, KEY_FILE_PREFIX

SKVBC_INIT_GRACE_TIME = 2

def start_replica_cmd(builddir, replica_id):
    """
    Return a command that starts an skvbc replica when passed to
    subprocess.Popen.

    Note each arguments is an element in a list.
    """
    statusTimerMilli = "500"
    viewChangeTimeoutMilli = "10000"
    path = os.path.join(builddir, "tests", "simpleKVBC", "TesterReplica", "skvbc_replica")
    return [path,
            "-k", KEY_FILE_PREFIX,
            "-i", str(replica_id),
            "-s", statusTimerMilli,
            "-v", viewChangeTimeoutMilli,
            "-e", str(True)
            ]

class SkvbcTestClientTxnSigning(unittest.TestCase):

    __test__ = False  # so that PyTest ignores this test scenario

    async def setup_skvbc(self, bft_network):
        bft_network.start_all_replicas()
        await trio.sleep(SKVBC_INIT_GRACE_TIME)
        return kvbc.SimpleKVBCProtocol(bft_network)

    def writeset(self, skvbc, max_size, keys=None):
        writeset_keys = skvbc.random_keys(random.randint(0, max_size)) if keys is None else keys
        writeset_values = skvbc.random_values(len(writeset_keys))
        return list(zip(writeset_keys, writeset_values))

    async def negative_tests_write(self, bft_network, corrupt_param={}):
        skvbc = await self.setup_skvbc(bft_network)
        client = bft_network.random_client()
        read_set = set()
        write_set = self.writeset(skvbc, 2)
        reply = await client.write(skvbc.write_req(read_set, write_set, 0))
        read_set = set()
        write_set = self.writeset(skvbc, 2)
        try:
            reply = await client.write(skvbc.write_req(read_set, write_set, 0), corrupt_params=corrupt_param)
        except trio.TooSlowError as e:
            pass

    async def assert_verification_metrics(self, bft_network, num_requests):

        for i in bft_network.all_replicas():
            num_signatures_verified = await bft_network.get_metric(
                i, bft_network, 'Counters', "external_client_request_signatures_verified", "signature_manager")
            
            assert num_signatures_verified == num_requests, \
                f"Expected {num_requests} signature verifications for replica {i}. Received {num_signatures_verified}"
            
            verification_failures_participant_id = await bft_network.get_metric(
                i, bft_network, 'Counters', "signature_verification_failed_on_unrecognized_participant_id", "signature_manager")
            
            assert verification_failures_participant_id == 0

    async def assert_failed_metrics(self, bft_network, num_requests, cannot_sign=False):
        
        for i in bft_network.all_replicas():
            num_signatures_failed = await bft_network.get_metric(
                i, bft_network, 'Counters', "external_client_request_signature_verification_failed", "signature_manager")

            if cannot_sign:
                assert num_signatures_failed == 0, \
                f"Number of signatures failed ({num_signatures_failed}) should be 0, because no signing takes place"
            else:
                assert num_signatures_failed > 0, f"Number of signatures failed ({num_signatures_failed}) should be greater than 0"
                assert num_signatures_failed > num_requests, \
                    f"Number of signatures failed {num_signatures_failed} should be more than the number of requests {num_requests}"

            verification_failures_participant_id = await bft_network.get_metric(
                i, bft_network, 'Counters', "signature_verification_failed_on_unrecognized_participant_id", "signature_manager")
            
            assert verification_failures_participant_id == 0

    @unittest.skipIf(environ.get('TXN_SIGNING_ENABLED', "").lower() != "true", "Transaction Signing is disabled")
    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_positive_flow_on_read(self, bft_network):
        """
        xxx
        """
        NUM_OF_SEQ_READS = 1000 # This is the minimum amount to update the aggregator
        skvbc = await self.setup_skvbc(bft_network)

        for i in range(NUM_OF_SEQ_READS):
            client = bft_network.random_client()
            await client.read(skvbc.get_last_block_req())

        await self.assert_verification_metrics(bft_network, NUM_OF_SEQ_READS)

    @unittest.skipIf(environ.get('TXN_SIGNING_ENABLED', "").lower() != "true", "Transaction Signing is disabled")
    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_positive_write_pre_exec_disabled(self, bft_network):
        """
        xxx
        """
        NUM_OF_SEQ_WRITES = 1000 # This is the minimum amount to update the aggregator
        skvbc = await self.setup_skvbc(bft_network)

        for i in range(NUM_OF_SEQ_WRITES):
            client = bft_network.random_client()
            read_set = set()
            write_set = self.writeset(skvbc, 2)
            reply = await client.write(skvbc.write_req(read_set, write_set, 0))

        await self.assert_verification_metrics(bft_network, NUM_OF_SEQ_WRITES)

    @unittest.skipIf(environ.get('TXN_SIGNING_ENABLED', "").lower() != "true", "Transaction Signing is disabled")
    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_negative_corrupt_signature(self, bft_network):
        """
        xxx
        """
        skvbc = await self.setup_skvbc(bft_network)

        client = bft_network.random_client()
        try:
            await client.read(skvbc.get_last_block_req(), corrupt_params={"corrupt_signature", ""})
        except trio.TooSlowError as e:
            pass

        await self.assert_failed_metrics(bft_network, 1)

    @unittest.skipIf(environ.get('TXN_SIGNING_ENABLED', "").lower() != "true", "Transaction Signing is disabled")
    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_negative_corrupt_msg(self, bft_network):
        """
        xxx
        """
        await self.negative_tests_write(bft_network, {"corrupt_msg": ""})
        await self.assert_failed_metrics(bft_network, 2)

    @unittest.skipIf(environ.get('TXN_SIGNING_ENABLED', "").lower() != "true", "Transaction Signing is disabled")
    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_negative_wrong_signature_length(self, bft_network):
        """
        xxx
        """
        await self.negative_tests_write(bft_network, {"wrong_signature_length": ""})
        await self.assert_failed_metrics(bft_network, 2, cannot_sign=True)

    @unittest.skipIf(environ.get('TXN_SIGNING_ENABLED', "").lower() != "true", "Transaction Signing is disabled")
    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_negative_wrong_msg_length(self, bft_network):
        """
        xxx
        """
        await self.negative_tests_write(bft_network, {"wrong_msg_length": ""})
        await self.assert_failed_metrics(bft_network, 2)

    @unittest.skipIf(environ.get('TXN_SIGNING_ENABLED', "").lower() != "true", "Transaction Signing is disabled")
    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_negative_wrong_id_0(self, bft_network):
        """
        xxx
        """
        await self.negative_tests_write(bft_network, {"wrong_id": 0})
        await self.assert_failed_metrics(bft_network, 2, cannot_sign=True)

    @unittest.skipIf(environ.get('TXN_SIGNING_ENABLED', "").lower() != "true", "Transaction Signing is disabled")
    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_negative_wrong_id_1000(self, bft_network):
        """
        xxx
        """
        await self.negative_tests_write(bft_network, {"wrong_id": 1000})
        await self.assert_failed_metrics(bft_network, 2, cannot_sign=True)

