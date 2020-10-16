# Concord
#
# Copyright (c) 2019 VMware, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache 2.0 license (the "License").
# You may not use this product except in compliance with the Apache 2.0 License.
#
# This product may include a number of subcomponents with separate copyright
# notices and license terms. Your use of these subcomponents is subject to the
# terms and conditions of the subcomponent's license, as noted in the LICENSE
# file.
import subprocess
import time
from re import split
from abc import ABC, abstractmethod
from itertools import combinations
from collections import namedtuple
from functools import partial

#DropRule = namedtuple('DropRule', ['src_node_id', 'dst_node_id', 'drop_rate_percentage', 'is_triggered'])

class NetworkPartitioningAdversary(ABC):
    """Represents an adversary capable of inflicting network partitioning"""

    BFT_NETWORK_PARTITIONING_RULE_CHAIN = "bft-network-partitioning"

    def __init__(self, bft_network):
        self.bft_network = bft_network
        self.connections = {}
        self.all_client_ids = bft_network.all_client_ids()
        self.comm_type = self.bft_network.comm_type() 
        assert self.comm_type == "tcp_tls" or self.comm_type == "udp"

    def __enter__(self):
        """context manager method for 'with' statements"""
        self._init_bft_network_rule_chain()
        if self.comm_type == "tcp_tls":
            self._set_replica_to_replica_connections_port_pairs(3.0)
        return self

    def __exit__(self, *args):
        """context manager method for 'with' statements"""
        self._remove_bft_network_rule_chain()

    @abstractmethod
    def interfere(self):
        """ This is where the actual malicious behavior is defined """
        pass

    def _init_bft_network_rule_chain(self):
        subprocess.run(
            ["iptables", "-N", self.BFT_NETWORK_PARTITIONING_RULE_CHAIN],
            check=True)
        subprocess.run(
            ["iptables", "-A", "INPUT",
             "-s", "localhost", "-d", "localhost",
             "-j", self.BFT_NETWORK_PARTITIONING_RULE_CHAIN],
            check=True)

    def _remove_bft_network_rule_chain(self):
        subprocess.run(
            ["iptables", "-D", "INPUT",
            "-s", "localhost", "-d", "localhost",
            "-j", self.BFT_NETWORK_PARTITIONING_RULE_CHAIN],
            check=True)
        subprocess.run(
            ["iptables", "-F", self.BFT_NETWORK_PARTITIONING_RULE_CHAIN], check=True)
        subprocess.run(
            ["iptables", "-X", self.BFT_NETWORK_PARTITIONING_RULE_CHAIN], check=True)

    def _port_to_node_id(self, port, other_port, pid=None):
        node_id = None
        if port < other_port:
            # tcp server port
            node_id = self.bft_network.node_id_from_data_port(port)
        elif pid:
            # tcp client port. the node id belongs to a client node or a replica
            node_id = self.bft_network.replica_id_from_pid(pid)
        else:
            fuser_output = subprocess.run(['fuser', str(port) + '/tcp'], check=True,  universal_newlines=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc_id = int(fuser_output.stdout.lstrip())
            node_id = self.bft_network.replica_id_from_pid(proc_id)

        if node_id is None:
            # this is a client node unknown port, search in all clients
            for id in self.all_client_ids:
                client = self.bft_network.get_client(id)
                if port in client.get_connections_port_list():
                    node_id = id
                    break
        assert node_id is not None
        return node_id

    def _set_replica_to_replica_connections_port_pairs(self, time_to_wait_sec=3.0, time_between_retries=0.25):
        # It might take time for all replicas to connect to each other
        assert isinstance(time_to_wait_sec, float) and isinstance(time_between_retries, float)
        wait_until_time = time.time() + time_to_wait_sec
        server_data_ports = [self.bft_network.data_port_from_node_id(i)
                                  for i in self.bft_network.all_replicas()]
        all_connections_established = False
        num_replicas = self.bft_network.config.n
        # Rules to calculate num_expected_connections:
        # 1) Each client/replica connect to all other replicas with lower ID. Hence, replica 0 does not connect to 
        # anyone. 
        # 2) Each active client connects to all other replicas.
        # 3) Clients do not connect to each other. 
        # 4) Each connection is bi-directional (hence 2 lines in output.
        # 5) Each connection is uni-directional for our purpose.
        # So between replicas we get 2 * (0 + 1 + 2... + N-1) = N * (N -1) connections, where N is the number of replicas
        # And for the clients <-> replicas we get 2 * N * num_clients connections
        num_expected_connections = num_replicas * (num_replicas - 1) + (len(self.all_client_ids) * num_replicas * 2)
        while time.time() < wait_until_time:
            try:
                netstat_output = subprocess.run(['netstat', '-tpun'],
                                            check=True, universal_newlines=True,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                grep_format = "127.0.0.1:%d.*ESTABLISHED"
                grep_str = ""
                grep_reg_or = "\\|"
                for i in range(len(server_data_ports)):
                    grep_str += (grep_format % server_data_ports[i]) + grep_reg_or
                grep_str = grep_str[:len(grep_str) - len(grep_reg_or)]
                grep_output = subprocess.run(['grep', grep_str],
                                            check=True, universal_newlines=True, input=netstat_output.stdout,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                if len(grep_output.stdout.splitlines()) == num_expected_connections:
                    all_connections_established = True
                    break
                else:
                    time.sleep(time_between_retries)
                    continue
            except subprocess.CalledProcessError:
                time.sleep(time_between_retries)
                continue
        assert all_connections_established

        for line in grep_output.stdout.splitlines():
            tokens = list(filter(None, split(' |:|/', line)))
            src_port = int(tokens[4])
            dst_port = int(tokens[6])
            src_proc_id = int(tokens[8])
            assert (src_port in server_data_ports) ^ (dst_port in server_data_ports)

            src_node_id = self._port_to_node_id(src_port, dst_port, src_proc_id)
            dst_node_id = self._port_to_node_id(dst_port, src_port)

            self.connections[(src_node_id, dst_node_id)] = (src_port, dst_port)
        assert len(self.connections) == num_expected_connections
        # Uncomment  to print all connections
        #from pprint import pprint; pprint(self.connections)

    def _drop_packets_between(self, src_node_id, dst_node_id, drop_rate_percentage=100):
        if self.comm_type == "tcp_tls":
            (src_port, dst_port) = self.connections[(src_node_id, dst_node_id)]
        else:
            src_port = bft_network.data_port_from_node_id(src_node_id)
            dst_port = bft_network.data_port_from_node_id(dst_node_id)
            pass

        self._drop_packets_between_ports(src_port, dst_port, drop_rate_percentage)

    def _drop_packets_between_ports(self, src_port, dst_port, drop_rate_percentage=100):
        assert 0 <= drop_rate_percentage <= 100
        drop_rate = drop_rate_percentage / 100
        subprocess.run(
            ["iptables", "-A", self.BFT_NETWORK_PARTITIONING_RULE_CHAIN,
             "-p", "tcp" if self.comm_type == "tcp_tls" else "udp",
             "--sport", str(src_port), "--dport", str(dst_port),
             "-m", "statistic", "--mode", "random",
             "--probability", str(drop_rate),
             "-j", "DROP"],
            check=True
        )

class PassiveAdversary(NetworkPartitioningAdversary):
    """ Adversary does nothing = synchronous network """

    def interfere(self):
        pass

class PrimaryIsolatingAdversary(NetworkPartitioningAdversary):
    """ Adversary that intercepts and drops all outgoing packets from the current primary """

    async def interfere(self):
        primary = await self.bft_network.get_current_primary()
        #primary_port = self.bft_network.replicas[primary].port

        non_primary_replicas = self.bft_network.all_replicas(without={primary})
        for replica in non_primary_replicas:
            #replica_port = self.bft_network.replicas[replica].port
            self._drop_packets_between(primary, replica)

class PacketDroppingAdversary(NetworkPartitioningAdversary):
    """ Adversary that drops random packets between all replicas """

    def __init__(self, bft_network, drop_rate_percentage=50):
        self.drop_rate_percentage = drop_rate_percentage
        super(PacketDroppingAdversary, self).__init__(bft_network)

    def interfere(self):
        # drop some packets between every two replicas
        for connection in combinations(self.bft_network.all_replicas(), 2):
            self._drop_packets_between(connection[0], connection[1], self.drop_rate_percentage)

class ReplicaSubsetIsolatingAdversary(NetworkPartitioningAdversary):
    """
    Adversary that isolates a sub-set of replicas,
    both from other replicas, as well as from the clients.
    """

    def __init__(self, bft_network, replicas_to_isolate):
        assert len(replicas_to_isolate) < bft_network.config.n
        self.replicas_to_isolate = replicas_to_isolate
        super(ReplicaSubsetIsolatingAdversary, self).__init__(bft_network)

    def interfere(self):
        other_replicas = set(self.bft_network.all_replicas()) - set(self.replicas_to_isolate)
        for ir in self.replicas_to_isolate:
            for r in other_replicas:
                self._drop_packets_between(ir, r)
                self._drop_packets_between(r, ir)

        for ir in self.replicas_to_isolate:
            for client_id in self.all_client_ids:
                #if self.comm_type == "udp" or len(c.ssl_streams) > 0:
                #     # active client
                #     self._drop_packets_between(c.client_id, ir)
                #     self._drop_packets_between(ir, c.client_id)
                # else:
                #     # Inactive tcp client
                #     server_port = self.bft_network.data_port_from_node_id(ir)
                #     c.register_interference_cb(ir, 
                #         [ lambda port: self._drop_packets_between_ports(server_port, port),
                #         lambda port: self._drop_packets_between_ports(port, server_port)])
                self._drop_packets_between(client_id, ir)
                self._drop_packets_between(ir, client_id)

class ReplicaSubsetOneWayIsolatingAdversary(NetworkPartitioningAdversary):
    """
    Adversary that isolates all messages except client requests
    to a subset of replicas. The Replicas in the subset will be able 
    to send msgs to other replicas in the network, but anything addressed
    to them by other replicas will be dropped.
    """

    def __init__(self, bft_network, replicas_to_isolate):
        assert len(replicas_to_isolate) < bft_network.config.n
        self.replicas_to_isolate = replicas_to_isolate
        super(ReplicaSubsetOneWayIsolatingAdversary, self).__init__(bft_network)

    def interfere(self):
        for ir in self.replicas_to_isolate:
            for r in self.bft_network.all_replicas():
                #isolated_replica_port = self.bft_network.replicas[ir].port
                #other_replica_port = self.bft_network.replicas[r].port
                if ir != r:
                    self._drop_packets_between(ir, r)

