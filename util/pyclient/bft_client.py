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

# This code requires python 3.5 or later
import struct
import trio
import time
import ssl
import os

import bft_msgs
import replica_specific_info as rsi
from bft_config import Config, Replica
from abc import ABC, abstractmethod

# All test communication expects ports to start from 3710
BASE_PORT = 3710

class ReqSeqNum:
    def __init__(self):
        self.time_since_epoch_milli = int(time.time() * 1000)
        self.count = 0
        self.max_count = 0x3FFFFF
        self.max_count_len = 22

    def next(self):
        """
        Calculate the next req_seq_num.
        Return the calculated value as an int sized for 64 bits
        """
        milli = int(time.time() * 1000)
        if milli > self.time_since_epoch_milli:
            self.time_since_epoch_milli = milli
            self.count = 0
        else:
            if self.count == self.max_count:
                self.time_since_epoch_milli += 1
                self.count = 0
            else:
                self.count += 1
        return self.val()

    def val(self):
        """ Return an int sized for 64 bits """
        assert (self.count <= self.max_count)
        r = self.time_since_epoch_milli << self.max_count_len
        r = r | self.count
        return r

class MofNQuorum:
    def __init__(self, replicas, required):
        self.replicas = replicas
        self.required = required

    @classmethod
    def LinearizableQuorum(cls, config, replicas):
        f = config.f
        c = config.c
        return MofNQuorum(replicas, 2 * f + c + 1)

    @classmethod
    def ByzantineSafeQuorum(cls, config, replicas):
        f = config.f
        return MofNQuorum(replicas, f + 1)

    @classmethod
    def All(cls, config, replicas):
        return MofNQuorum(replicas, len(replicas))

class BftClient(ABC):
    def __init__(self, config, replicas):
        self.config = config
        self.replicas = replicas
        self.req_seq_num = ReqSeqNum()
        self.client_id = config.id
        self.primary = None
        self.reply = None
        self.retries = 0
        self.msgs_sent = 0
        self.replies_manager = rsi.RepliesManager()
        self.rsi_replies = dict()
        self.comm_prepared = False

    @abstractmethod
    async def __aenter__(self):
        pass

    @abstractmethod
    async def __aexit__():
        pass

    @abstractmethod
    async def _send_data(self, data, replica):
        pass

    @abstractmethod
    async def _comm_prepare(self, read_only):
        pass

    async def write(self, msg, seq_num=None, cid=None, pre_process=False, m_of_n_quorum=None):
        """ A wrapper around sendSync for requests that mutate state """
        return await self.sendSync(msg, False, seq_num, cid, pre_process, m_of_n_quorum)

    async def read(self, msg, seq_num=None, cid=None, m_of_n_quorum=None):
        """ A wrapper around sendSync for requests that do not mutate state """
        return await self.sendSync(msg, True, seq_num, cid, m_of_n_quorum=m_of_n_quorum)

    async def sendSync(self, msg, read_only, seq_num=None, cid=None, pre_process=False, m_of_n_quorum=None):
        """
        Send a client request and wait for a m_of_n_quorum (if None, it will set to 2F+C+1 quorum) of replies.

        Return a single reply message if a quorum of replies matches.
        Otherwise, raise a trio.TooSlowError indicating the request timed out.

        Retry Strategy:
            If the request is a write and the primary is known then send only to
            the primary on the first attempt. Otherwise, if the request is read
            only or the primary is unknown, then send to all replicas on the
            first attempt.

            After `config.retry_timeout_milli` without receiving a quorum of
            identical replies, then clear the replies and send to all replicas.
            Continue this strategy every `retry_timeout_milli` until
            `config.req_timeout_milli` elapses. If `config.req_timeout_milli`
            elapses then a trio.TooSlowError is raised.

         Note that this method also binds the socket to an appropriate port if
         not already bound.
        """
        if not self.comm_prepared:
            await self._comm_prepare(read_only)

        if seq_num is None:
            seq_num = self.req_seq_num.next()

        if cid is None:
            cid = str(seq_num)
        data = bft_msgs.pack_request(
            self.client_id, seq_num, read_only, self.config.req_timeout_milli, cid, msg, pre_process)

        if m_of_n_quorum is None:
            m_of_n_quorum = MofNQuorum.LinearizableQuorum(self.config, [r.id for r in self.replicas])

        # Raise a trio.TooSlowError exception if a quorum of replies
        try:
            with trio.fail_after(self.config.req_timeout_milli / 1000):
                self._reset_on_new_request()
                return await self._send_receive_loop(data, read_only, m_of_n_quorum)
        except trio.TooSlowError:
            print("TooSlowError thrown from client_id", self.client_id, "for seq_num", seq_num)
            raise trio.TooSlowError
        finally:
            pass

    def _reset_on_retry(self):
        """Reset any state that must be reset during retries"""
        self.primary = None
        self.retries += 1
        if self.retries % 30 == 0:
            self.rsi_replies = dict()
            self.replies_manager.clear_replies()

    def _reset_on_new_request(self):
        """Reset any state that must be reset during new requests"""
        self.reply = None
        self.retries = 0
        self.rsi_replies = dict()
        self.replies_manager.clear_replies()

    async def _send_receive_loop(self, data, read_only, m_of_n_quorum):
        """
        Send and wait for a quorum of replies. Keep retrying if a quorum
        isn't received. Eventually the max request timeout from the
        outer scope will fire cancelling all sub-scopes and their coroutines
        including this one.
        """
        dest_replicas = [r for r in self.replicas if r.id in m_of_n_quorum.replicas]
        while self.reply is None:
            with trio.move_on_after(self.config.retry_timeout_milli / 1000):
                async with trio.open_nursery() as nursery:
                    if read_only or self.primary is None:
                        await self._send_to_replicas(data, dest_replicas)
                    else:
                        await self._send_to_primary(data)
                    nursery.start_soon(self._recv, m_of_n_quorum.required, dest_replicas, nursery.cancel_scope)
            if self.reply is None:
                self._reset_on_retry()
        return self.reply

    async def _send_to_primary(self, request):
        """Send a serialized request to the primary"""
        async with trio.open_nursery() as nursery:
            nursery.start_soon(self._sendto, request, self.primary)

    async def _send_to_replicas(self, request, replicas):
        """Send a serialized request to all replicas"""
        async with trio.open_nursery() as nursery:
            for replica in replicas:
                nursery.start_soon(self._sendto, request, replica)

    async def _sendto(self, request, replica):
        """Send a request"""
        if await self._send_data(request, replica):
            self.msgs_sent += 1

    def _valid_reply(self, header, sender, dest_replicas):
        return self.req_seq_num.val() == header.req_seq_num and sender in dest_replicas

    def get_rsi_replies(self):
        """
        Return a dictionary of {id: data} of the replicas specific information.
        This method should be called after the send has done and before initiating a new request
        """
        return self.rsi_replies

    def _process_received_msg(self, data, sender, replicas_addr, required_replies, cancel_scope):
        rsi_msg = rsi.MsgWithReplicaSpecificInfo(data, sender)
        header, reply = rsi_msg.get_common_reply()
        if self._valid_reply(header, rsi_msg.get_sender_id(), replicas_addr):
            quorum_size = self.replies_manager.add_reply(rsi_msg)
            if quorum_size == required_replies:
                self.reply = reply
                self.rsi_replies = self.replies_manager.get_rsi_replies(rsi_msg.get_matched_reply_key())
                self.primary = self.replicas[header.primary_id]
                cancel_scope.cancel()

class UdpClient(BftClient):
    def __init__(self, config, replicas):
        super().__init__(config, replicas)
        self.sock = trio.socket.socket(trio.socket.AF_INET, trio.socket.SOCK_DGRAM)
        self.port = BASE_PORT + 2 * self.client_id

    async def _comm_prepare(self, read_only):
        """ Bind the socket to address, where each port is a function of its client_id """
        await self.sock.bind(('localhost', self.port))
        self.comm_prepared = True

    async def _send_data(self, data, replica):
        await self.sock.sendto(data, (replica.ip, replica.port))
        return True

    async def _recv(self, required_replies, dest_replicas, cancel_scope):
        """
        Receive reply messages until a quorum is achieved or the enclosing
        cancel_scope times out.
        """
        replicas_addr = [(r.ip, r.port) for r in dest_replicas]
        while True:
            data, sender = await self.sock.recvfrom(self.config.max_msg_size)
            self._process_received_msg(data, sender, replicas_addr, required_replies, cancel_scope)

    async def __aenter__(self):
        """context manager method for 'with' statements"""
        return self

    async def __aexit__(self):
        """context manager method for 'with' statements"""
        self.sock.close()

class TcpTlsClient(BftClient):
    # In create_tls_certs.sh - openssl command line utility uses CN(certificate name) in the subj field.
    # This is the host name (domain name) to be verified.
    CERT_DOMAIN_FORMAT="node%dser"
    # Taken from TlsTCPCommunication.cpp
    MSG_HEADER_SIZE=4

    def __init__(self, config, replicas, bft_network):
        super().__init__(config, replicas)
        self.ssl_streams = dict()
        self.bft_network = bft_network
        self.certs_generated = False

    async def _comm_prepare(self, read_only):
        """establish a TLS over TCP connections to all replicas"""
        if not (read_only or self.primary is None):
            return
        if not self.certs_generated:
            self.bft_network.generate_tls_certs(1, self.client_id)
            self.certs_generated = True
        self.comm_retries = 0
        with trio.move_on_after(2.0) as cancel_scope:
            async with trio.open_nursery() as nursery:
                for replica in self.replicas:
                    if (replica.ip, replica.port) not in self.ssl_streams.keys():
                        nursery.start_soon(self._establish_ssl_stream, replica)
        self.comm_prepared = (len(self.replicas) == len(self.ssl_streams))

    def _get_private_key_path(self, replica_id, is_client=False):
        cert_type = "client" if is_client else "server"
        return os.path.join(self.config.certs_path, str(replica_id), cert_type, "pk.pem")

    def _get_cert_path(self, replica_id, is_client=False):
        cert_type = "client" if is_client else "server"
        return os.path.join(self.config.certs_path, str(replica_id), cert_type, cert_type + ".cert")

    async def _establish_ssl_stream(self, dest_replica):
        #print(f"===start {(dest_replica.ip, dest_replica.port)}")
        while True:
            try:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                server_cert_path = self._get_cert_path(dest_replica.id, False)
                client_cert_path = self._get_cert_path(self.client_id, True)
                client_pk_path = self._get_private_key_path(self.client_id, True)
                ssl_context.load_verify_locations(cafile=server_cert_path)
                ssl_context.load_cert_chain(client_cert_path, client_pk_path)
                server_hostname = self.CERT_DOMAIN_FORMAT % dest_replica.id
                #print(f"{server_cert_path} {client_cert_path} {client_pk_path} {server_hostname}")
                tcp_stream = await trio.open_tcp_stream(str(dest_replica.ip), int(dest_replica.port), local_address="localhost")
                ssl_stream = trio.SSLStream(tcp_stream, ssl_context, server_hostname=server_hostname, https_compatible=False)
                await ssl_stream.do_handshake()
                self.ssl_streams[(dest_replica.ip, dest_replica.port)] = ssl_stream
                #print(f"===connected to {(dest_replica.ip, dest_replica.port)}")
                break
            except (OSError, trio.BrokenResourceError):
                self.comm_retries += 1
                await trio.sleep(0.5)
                continue

    async def _send_data(self, data, dest_replica):
        dest_addr = (dest_replica.ip, dest_replica.port)
        if dest_addr not in self.ssl_streams.keys():
            return False
        data_len = len(data)
        out_buff = bytearray(data_len.to_bytes(self.MSG_HEADER_SIZE, "little"))
        out_buff += bytearray(data)
        #print(f"sending src={self.client_id} to dest={dest_addr} total_len={len(out_buff)} out_buff={['{0:0>2X}'.format(b) for b in out_buff]}")
        #print(f"sending src={self.client_id} to dest={dest_addr} total_len={len(out_buff)}")
        stream = self.ssl_streams[dest_addr]
        try:
            await stream.send_all(out_buff)
        except (trio.BrokenResourceError, trio.ClosedResourceError):
             await stream.aclose()
             del self.ssl_streams[dest_addr]
             self.comm_prepared = False
             return False
        #print(f"sent to {dest_addr} data_len={len(data)}")
        return True

    async def _stream_recv_some(self, out_data, dest_addr, stream, num_bytes):
        try:
            out_data += await stream.receive_some(num_bytes)
            return True
        except (trio.BrokenResourceError, trio.ClosedResourceError):
            await stream.aclose()
            del self.ssl_streams[dest_addr]
            self.comm_prepared = False
            return False

    async def _receive_from_replica(self, dest_addr, replicas_addr, required_replies, cancel_scope):
        data = bytearray()
        stream = self.ssl_streams[dest_addr]
        #print(f"receiving from {dest_addr}")
        while len(data) < self.MSG_HEADER_SIZE:
            if not await self._stream_recv_some(data, dest_addr, stream, self.MSG_HEADER_SIZE):
                return
        payload_size = int.from_bytes(data[:self.MSG_HEADER_SIZE], "little")
        del data[:self.MSG_HEADER_SIZE]
        while len(data) < payload_size:
            if not await self._stream_recv_some(data, dest_addr, stream, payload_size - len(data)):
                return
        #print(f"received from {dest_addr}")
        self._process_received_msg(bytes(data), dest_addr, replicas_addr, required_replies, cancel_scope)

    async def _recv(self, required_replies, dest_replicas, cancel_scope):
        """
        Receive reply messages until a quorum is achieved or the enclosing
        cancel_scope times out.
        """
        replicas_addr = [(r.ip, r.port) for r in dest_replicas]
        async with trio.open_nursery() as nursery:
            for dest_addr in replicas_addr:
                if dest_addr in self.ssl_streams.keys():
                    nursery.start_soon(self._receive_from_replica, dest_addr, replicas_addr, required_replies,
                                       nursery.cancel_scope)
    async def __aenter__(self):
        pass

    async def __aexit__(self):
        for stream in self.ssl_streams.values():
            await stream.aclose()


