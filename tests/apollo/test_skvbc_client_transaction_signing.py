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
#import random
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

    @unittest.skipIf(environ.get('TXN_SIGNING_ENABLED', "").lower() != "true", "Transaction Signing is disabled")
    @with_trio
    @with_bft_network(start_replica_cmd, selected_configs=lambda n, f, c: n == 7)
    async def test_happy_flow_on_read(self, bft_network):
        """
        xxx
        """
        NUM_OF_SEQ_READS = 1000 # This is the minimal amount to update the aggregator
        bft_network.start_all_replicas()
        await trio.sleep(SKVBC_INIT_GRACE_TIME)
        skvbc = kvbc.SimpleKVBCProtocol(bft_network)

        for i in range(NUM_OF_SEQ_READS):
            client = bft_network.random_client()
            await client.read(skvbc.get_last_block_req())

        for i in bft_network.all_replicas():
            num_signatures_verified = await bft_network.get_metric(
                i, bft_network, 'Counters', "external_client_request_signatures_verified", "signature_manager")
            #num_signatures_failed = await bft_network.get_metric(
            #    i, bft_network, 'Counters', "external_client_request_signatures_verified", "signature_manager")
            print(f"replica {i} num_signatures_verified={num_signatures_verified}")
            