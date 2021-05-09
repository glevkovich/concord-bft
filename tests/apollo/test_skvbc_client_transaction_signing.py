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

# from util import blinking_replica
from util import skvbc as kvbc
from util.bft import with_trio, with_bft_network, KEY_FILE_PREFIX

SKVBC_INIT_GRACE_TIME = 5


def start_replica_cmd(builddir, replica_id):
    """
    Return a command that starts an skvbc replica when passed to
    subprocess.Popen.

    Note each arguments is an element in a list.
    """
    statusTimerMilli = "500"
    viewChangeTimeoutMilli = "10000"
    path = os.path.join(builddir, "tests", "simpleKVBC",
                        "TesterReplica", "skvbc_replica")
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
        writeset_keys = skvbc.random_keys(
            random.randint(0, max_size)) if keys is None else keys
        writeset_values = skvbc.random_values(len(writeset_keys))
        return list(zip(writeset_keys, writeset_values))

    async def corrupted_write(self, bft_network, skvbc, corrupt_params, client=None):
        assert(len(corrupt_params) > 0 and corrupt_params != None)
        client = bft_network.random_client() if client == None else client
        read_set = set()
        write_set = self.writeset(skvbc, 2)
        await client.write(skvbc.write_req(read_set, write_set, 0))
        read_set = set()
        write_set = self.writeset(skvbc, 2)
        try:
            await client.write(skvbc.write_req(read_set, write_set, 0), corrupt_params=corrupt_params)
        except trio.TooSlowError as e:
            pass

    async def corrupted_read(self, bft_network, skvbc, corrupt_params, client=None):
        assert(len(corrupt_params) > 0 and corrupt_params != None)
        client = bft_network.random_client() if client == None else client
        try:
            await client.read(skvbc.get_last_block_req(), corrupt_params=corrupt_params)
        except trio.TooSlowError as e:
            pass

    async def read_n_times(self, bft_network, skvbc, num_reads, client=None):
        for i in range(num_reads):
            client = bft_network.random_client() if client == None else client
            await client.read(skvbc.get_last_block_req())

    async def write_n_times(self, bft_network, skvbc, num_writes, client=None, pre_exec=False):
        for i in range(num_writes):
            client = bft_network.random_client() if client == None else client
            read_set = set()
            write_set = self.writeset(skvbc, 2)
            await client.write(skvbc.write_req(read_set, write_set, 0), pre_process=pre_exec)

    async def send_batch_write_with_pre_execution(self, skvbc, bft_network, num_writes, batch_size, client=None, long_exec=False):
        num_batches = num_writes//batch_size
        msg_batch = []
        batch_seq_nums = []
        client = bft_network.random_client() if client == None else client
        for i in range(num_batches):
            for j in range(batch_size):
                readset = set()
                writeset = self.writeset(skvbc, 2)
                msg_batch.append(skvbc.write_req(readset, writeset, 0, long_exec))
                seq_num = client.req_seq_num.next()
                batch_seq_nums.append(seq_num)
        replies = await client.write_batch(msg_batch, batch_seq_nums)
        for seq_num, reply_msg in replies.items():
            self.assertTrue(skvbc.parse_reply(reply_msg.get_common_data()).success)

    async def get_metrics(self, bft_network):
        metrics = [{} for _ in range(bft_network.num_total_replicas())]
        for i in bft_network.all_replicas():
            metrics[i]["num_signatures_failed_verification"] = int(await bft_network.get_metric(
                i, bft_network, 'Counters', "external_client_request_signature_verification_failed", "signature_manager"))
            metrics[i]["num_signatures_failed_on_unrecognized_participant_id"] = int(await bft_network.get_metric(
                i, bft_network, 'Counters', "signature_verification_failed_on_unrecognized_participant_id", "signature_manager"))
            metrics[i]["num_signatures_verified"] = int(await bft_network.get_metric(
                i, bft_network, 'Counters', "external_client_request_signatures_verified", "signature_manager"))
        return metrics

    async def assert_metrics(self,
                             bft_network,
                             expected_num_signatures_verified=0,
                             is_expected_signatures_failed_verification=False,
                             is_expected_signatures_failed_on_unrecognized_participant_id=False):

        metrics = await self.get_metrics(bft_network)
        for i in bft_network.all_replicas():
            if expected_num_signatures_verified != None:
                assert expected_num_signatures_verified == metrics[i]["num_signatures_verified"], \
                    f"expected_num_signatures_verified={expected_num_signatures_verified}; actual={metrics[i]['num_signatures_verified']}"

            if is_expected_signatures_failed_verification != None:
                if is_expected_signatures_failed_verification:
                    assert metrics[i]['num_signatures_failed_verification'] > 0, \
                    f"num_signatures_failed_verification={metrics[i]['num_signatures_failed_verification']}"
                else:
                    assert metrics[i]['num_signatures_failed_verification'] == 0, \
                        f"num_signatures_failed_verification={metrics[i]['num_signatures_failed_verification']}"

            if is_expected_signatures_failed_on_unrecognized_participant_id != None:
                if is_expected_signatures_failed_on_unrecognized_participant_id:
                    assert metrics[i]["num_signatures_failed_on_unrecognized_participant_id"] > 0
                else:
                    assert metrics[i]["num_signatures_failed_on_unrecognized_participant_id"] == 0
        return metrics

    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_positive_read(self, bft_network):
        """
        xxx
        """
        NUM_OF_SEQ_READS = 1000  # This is the minimum amount to update the aggregator
        skvbc = await self.setup_skvbc(bft_network)

        await self.read_n_times(bft_network, skvbc, NUM_OF_SEQ_READS)

        # The exact number of verification is larger, due to unknown primary + double verification on pre-prepare on unknown-primary
        # and the fact that we choose a random client which might have an unknown primary.
        # since the "steps" between updates are of 1000 in the source code - we can ne sure for now on the exact metric value
        await self.assert_metrics(bft_network, expected_num_signatures_verified=NUM_OF_SEQ_READS)

    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_positive_write_pre_exec_disabled(self, bft_network):
        """
        xxx
        """
        NUM_OF_SEQ_WRITES = 1000  # This is the minimum amount to update the aggregator
        skvbc = await self.setup_skvbc(bft_network)

        await self.write_n_times(bft_network, skvbc, NUM_OF_SEQ_WRITES)

        # The exact number of verification is larger, due to unknown primary + double verification on pre-prepare on unknown-primary
        # and the fact that we choose a random client which might have an unknown primary.
        # since the "steps" between updates are of 1000 in the source code - we can ne sure for now on the exact metric value
        await self.assert_metrics(bft_network, expected_num_signatures_verified=NUM_OF_SEQ_WRITES)

    # TODO - NOT WORKING
    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_positive_write_pre_exec_enabled(self, bft_network):
        """
        xxx
        """
        NUM_OF_SEQ_WRITES = 1000  # This is the minimum amount to update the aggregator
        skvbc = await self.setup_skvbc(bft_network)

        await self.write_n_times(bft_network, skvbc, NUM_OF_SEQ_WRITES, pre_exec=True)
        await self.assert_metrics(bft_network, expected_num_signatures_verified=NUM_OF_SEQ_WRITES)

    # TODO - NOT WORKING
    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_positive_write_batching_enabled(self, bft_network):
        """
        xxx
        """
        NUM_OF_SEQ_WRITES = 1000  # This is the minimum amount to update the aggregator
        skvbc = await self.setup_skvbc(bft_network)
        await self.send_batch_write_with_pre_execution(skvbc, bft_network, NUM_OF_SEQ_WRITES, 4, long_exec=False)

        # The exact number of verification is larger, due to unknown primary + double verification on pre-prepare on unknown-primary
        # and the fact that we choose a random client which might have an unknown primary.
        # since the "steps" between updates are of 1000 in the source code - we can ne sure for now on the exact metric value
        await self.assert_metrics(bft_network, expected_num_signatures_verified=NUM_OF_SEQ_WRITES)

    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_negative_corrupt_signature_and_msg(self, bft_network):
        """
        xxx
        """
        skvbc = await self.setup_skvbc(bft_network)
        corrupt_dict = {"corrupt_signature": "", "corrupt_msg": "",
                        "wrong_signature_length": "", "wrong_msg_length": ""}
        client = bft_network.random_client()

        for corrupt_pair in corrupt_dict:
            await self.corrupted_write(bft_network, skvbc, corrupt_pair, client)
            metrics1 = await self.assert_metrics(bft_network, expected_num_signatures_verified=None, is_expected_signatures_failed_verification=True)

            await self.write_n_times(bft_network, skvbc, 1, client)

            await self.corrupted_write(bft_network, skvbc, corrupt_pair, client)
            metrics2 = await self.assert_metrics(bft_network,
                                                 expected_num_signatures_verified=None,
                                                 is_expected_signatures_failed_verification=True)

            for i in bft_network.all_replicas():
                assert(metrics1[i]["num_signatures_failed_verification"] <=
                       metrics2[i]["num_signatures_failed_verification"])
                assert(metrics1[i]["num_signatures_failed_on_unrecognized_participant_id"] ==
                       metrics2[i]["num_signatures_failed_on_unrecognized_participant_id"])
                assert(metrics1[i]["num_signatures_verified"] <=
                       metrics2[i]["num_signatures_verified"])

    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_negative_wrong_client_id(self, bft_network):
        """
        xxx
        """
        skvbc = await self.setup_skvbc(bft_network)
        client = bft_network.random_client()
        corrupt_dict = {"wrong_client_id_as_replica_id": 0,
                        "wrong_client_id_as_unknown_id": 10000}
        
        for k, v in corrupt_dict.items():
            await self.corrupted_write(bft_network, skvbc, {k:v}, client)
            metrics1 = await self.assert_metrics(bft_network, expected_num_signatures_verified=None)

            await self.write_n_times(bft_network, skvbc, 1, client)

            await self.corrupted_write(bft_network, skvbc, {k:v}, client)
            metrics2 = await self.assert_metrics(bft_network, expected_num_signatures_verified=None)

            for i in bft_network.all_replicas():
                assert(metrics1[i]["num_signatures_failed_verification"] ==
                       metrics2[i]["num_signatures_failed_verification"])
                assert(metrics1[i]["num_signatures_failed_on_unrecognized_participant_id"] ==
                       metrics2[i]["num_signatures_failed_on_unrecognized_participant_id"])
                assert(metrics1[i]["num_signatures_verified"] ==
                       metrics2[i]["num_signatures_verified"])

    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_negative_wrong_client_id_as_other_participant_client_id(self, bft_network):
        """
        xxx
        """
        clients = bft_network.random_clients(2)
        skvbc = await self.setup_skvbc(bft_network)
        client, client2 = clients
        assert client.client_id != client2.client_id
        corrupt_dict = {"wrong_client_id_as_other_participant_client_id": client2.client_id}

        for k, v in corrupt_dict.items():
            await self.corrupted_write(bft_network, skvbc, {k:v}, client)
            metrics1 = await self.assert_metrics(bft_network,
                                                 expected_num_signatures_verified=None,
                                                 is_expected_signatures_failed_verification=True)

            await self.write_n_times(bft_network, skvbc, 1, client)

            await self.corrupted_write(bft_network, skvbc, {k:v}, client)
            metrics2 = await self.assert_metrics(bft_network,
                                                 expected_num_signatures_verified=None,
                                                 is_expected_signatures_failed_verification=True)

            for i in bft_network.all_replicas():
                assert(metrics1[i]["num_signatures_failed_verification"] <
                       metrics2[i]["num_signatures_failed_verification"])
                assert(metrics1[i]["num_signatures_failed_on_unrecognized_participant_id"] ==
                       metrics2[i]["num_signatures_failed_on_unrecognized_participant_id"])
                assert(metrics1[i]["num_signatures_verified"] <
                       metrics2[i]["num_signatures_verified"])
