// Concord
//
// Copyright (c) 2018-2021 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License"). You may not use this product except in
// compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright notices and license terms. Your use of
// these subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#include "bftengine/SimpleClient.hpp"
#include "ClientRequestMsg.hpp"
#include "assertUtils.hpp"
#include "ReplicaConfig.hpp"
#include "SigManager.hpp"

#include <cstring>

namespace bftEngine::impl {

// local helper functions

static uint16_t getSender(const ClientRequestMsgHeader* r) { return r->idOfClientProxy; }

static int32_t compRequestMsgSize(const ClientRequestMsgHeader* r) {
  return (sizeof(ClientRequestMsgHeader) + r->spanContextSize + r->requestLength + r->cidLength +
          r->reqSignatureLength);
}

uint32_t getRequestSizeTemp(const char* request)  // TODO(GG): change - TBD
{
  const ClientRequestMsgHeader* r = (ClientRequestMsgHeader*)request;
  return compRequestMsgSize(r);
}

ClientRequestMsg::Recorders ClientRequestMsg::histograms_;

// class ClientRequestMsg
ClientRequestMsg::ClientRequestMsg(NodeIdType sender,
                                   uint8_t flags,
                                   uint64_t reqSeqNum,
                                   uint32_t requestLength,
                                   const char* request,
                                   uint64_t reqTimeoutMilli,
                                   const std::string& cid,
                                   const concordUtils::SpanContext& spanContext,
                                   const char* requestSignature,
                                   uint32_t requestSignatureLen)
    : MessageBase(sender,
                  MsgCode::ClientRequest,
                  spanContext.data().size(),
                  sizeof(ClientRequestMsgHeader) + requestLength + cid.size() + requestSignatureLen) {
  // logical XOR - if requestSignatureLen is zero requestSignature must be null and vise versa
  ConcordAssert((requestSignature == nullptr) == (requestSignatureLen == 0));
  // set header
  setParams(sender, reqSeqNum, requestLength, flags, reqTimeoutMilli, cid, requestSignatureLen);

  // set span context
  char* position = body() + sizeof(ClientRequestMsgHeader);
  memcpy(position, spanContext.data().data(), spanContext.data().size());

  // set request data
  position += spanContext.data().size();
  memcpy(position, request, requestLength);

  // set correlation ID
  position += requestLength;
  memcpy(position, cid.data(), cid.size());

  // set signature
  if (requestSignature) {
    position += cid.size();
    memcpy(position, requestSignature, requestSignatureLen);
  }
}

ClientRequestMsg::ClientRequestMsg(NodeIdType sender)
    : MessageBase(sender, MsgCode::ClientRequest, 0, (sizeof(ClientRequestMsgHeader))) {
  msgBody()->flags &= EMPTY_CLIENT_REQ;
}

ClientRequestMsg::ClientRequestMsg(ClientRequestMsgHeader* body)
    : MessageBase(getSender(body), (MessageBase::Header*)body, compRequestMsgSize(body), false) {}

bool ClientRequestMsg::isReadOnly() const { return (msgBody()->flags & READ_ONLY_REQ) != 0; }

void ClientRequestMsg::validateImp(const ReplicasInfo& repInfo, bool validateSignature) const {
  const auto* header = msgBody();
  PrincipalId senderId = header->idOfClientProxy;
  ConcordAssert(senderId != repInfo.myId());
  auto minMsgSize = sizeof(ClientRequestMsgHeader) + header->cidLength + spanContextSize() + header->reqSignatureLength;
  const auto msgSize = size();
  uint16_t expectedSigLen = 0;
  std::stringstream msg;
  auto sigManager = SigManager::getInstance();
  bool isClientTransactionSigningEnabled = sigManager->isClientTransactionSigningEnabled();
  bool isIdOfExternalClient = repInfo.isIdOfExternalClient(senderId);
  bool doSigVerify = false;

  // LOG_INFO(GL, "1x1 " << __LINE__);
  if (!repInfo.isValidParticipantId(senderId)) {
    msg << "Invalid senderId " << senderId;
    LOG_ERROR(GL, msg.str());
    throw std::runtime_error(msg.str());
  }

  if (isIdOfExternalClient && isClientTransactionSigningEnabled) {
    // LOG_INFO(GL, "1x1 " << __LINE__);
    expectedSigLen = sigManager->getSigLength(senderId);
    if (0 == expectedSigLen) {
      msg << "Invalid expectedSigLen " << KVLOG(senderId);
      LOG_ERROR(GL, msg.str());
      throw std::runtime_error(msg.str());
    }
    doSigVerify = validateSignature;
    // LOG_INFO(GL, "1x1 " << __LINE__);
  }

  if (expectedSigLen != header->reqSignatureLength) {
    msg << "Unexpected request signature length: "
        << KVLOG(senderId,
                 expectedSigLen,
                 header->reqSignatureLength,
                 isIdOfExternalClient,
                 isClientTransactionSigningEnabled);
    LOG_ERROR(GL, msg.str());
    throw std::runtime_error(msg.str());
  }

  auto expectedMsgSize =
      sizeof(ClientRequestMsgHeader) + header->requestLength + header->cidLength + spanContextSize() + expectedSigLen;

  if ((msgSize < minMsgSize) || (msgSize != expectedMsgSize)) {
    msg << "Invalid msgSize: " << KVLOG(msgSize, minMsgSize, expectedMsgSize);
    LOG_ERROR(GL, msg.str());
    throw std::runtime_error(msg.str());
  }

  if (doSigVerify &&
      !sigManager->verifySig(
          senderId, requestBuf(), header->requestLength, requestSignature(), header->reqSignatureLength)) {
    std::stringstream msg;
    // todo - add info
    LOG_ERROR(GL, "Signature verification failed for " << KVLOG(senderId));
    msg << "Signature verification failed for: "
        << KVLOG(senderId, header->reqSeqNum, header->requestLength, header->reqSignatureLength, getCid(), this->senderId());
  }
  // LOG_INFO(GL, "1x1 " << __LINE__);
}

void ClientRequestMsg::setParams(NodeIdType sender,
                                 ReqId reqSeqNum,
                                 uint32_t requestLength,
                                 uint8_t flags,
                                 uint64_t reqTimeoutMilli,
                                 const std::string& cid,
                                 uint32_t requestSignatureLen) {
  auto* header = msgBody();
  header->idOfClientProxy = sender;
  header->timeoutMilli = reqTimeoutMilli;
  header->reqSeqNum = reqSeqNum;
  header->requestLength = requestLength;
  header->flags = flags;
  header->cidLength = cid.size();
  header->reqSignatureLength = requestSignatureLen;
}

std::string ClientRequestMsg::getCid() const {
  return std::string(body() + sizeof(ClientRequestMsgHeader) + msgBody()->requestLength + spanContextSize(),
                     msgBody()->cidLength);
}

char* ClientRequestMsg::requestSignature() const {
  const auto* header = msgBody();
  if (header->reqSignatureLength > 0) {
    return body() + sizeof(ClientRequestMsgHeader) + spanContextSize() + header->requestLength + header->cidLength;
  }
  return nullptr;
}

}  // namespace bftEngine::impl
