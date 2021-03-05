// Concord
//
// Copyright (c) 2020 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License"). You may not use this product except in
// compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright notices and license terms. Your use of
// these subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#pragma once

#include <memory>
#include <optional>

#include "communication/ICommunication.hpp"
#include "Logger.hpp"
#include "DynamicUpperLimitWithSimpleFilter.hpp"

#include "bftclient/config.h"
#include "matcher.h"
#include "msg_receiver.h"
#include "exception.h"
#include "metrics.h"
#include "diagnostics.h"
#include "bftengine/Crypto.hpp"

using namespace CryptoPP;

namespace bft::client {

class Client {
 public:
  Client(std::unique_ptr<bft::communication::ICommunication> comm, const ClientConfig& config);

  void setAggregator(const std::shared_ptr<concordMetrics::Aggregator>& aggregator) {
    metrics_.setAggregator(aggregator);
  }

  void stop() { communication_->Stop(); }

  // Send a message where the reply gets allocated by the callee and returned in a vector.
  // The message to be sent is moved into the caller to prevent unnecessary copies.
  //
  // Throws a BftClientException on error.
  Reply send(const WriteConfig& config, Msg&& request);
  Reply send(const ReadConfig& config, Msg&& request);
  bool isServing(int numOfReplicas, int requiredNumOfReplicas) const;

  // Useful for testing. Shouldn't be relied on in production.
  std::optional<ReplicaId> primary() { return primary_; }

 private:
  // Generic function for sending a read or write message.
  Reply send(const MatchConfig& match_config, const RequestConfig& request_config, Msg&& request, bool read_only);

  // Wait for messages until we get a quorum or a retry timeout.
  //
  // Return a Reply on quorum, or std::nullopt on timeout.
  std::optional<Reply> wait();

  // Extract a matcher configurations from operational configurations
  //
  // Throws BftClientException on error.
  MatchConfig writeConfigToMatchConfig(const WriteConfig&);
  MatchConfig readConfigToMatchConfig(const ReadConfig&);

  // This function creates a ClientRequestMsg or a ClientPreProcessRequestMsg depending upon config.
  //
  // Since both of these are just instances of a `ClientRequestMsgHeader` followed by the message
  // data, we construct them here, rather than relying on the type constructors embedded into the
  // bftEngine impl. This allows us to not have to link with the bftengine library, and also allows us
  // to return the messages as vectors with proper RAII based memory management.
  Msg makeClientMsg(const RequestConfig& req_config, Msg&& request, bool read_only, uint16_t client_id);

  MsgReceiver receiver_;

  std::unique_ptr<bft::communication::ICommunication> communication_;
  ClientConfig config_;
  logging::Logger logger_ = logging::getLogger("bftclient");

  // The client doesn't always know the current primary.
  std::optional<ReplicaId> primary_;

  // Each outstanding request matches replies using a new matcher.
  // If there are no outstanding requests, then this is a nullopt;
  std::optional<Matcher> outstanding_request_;

  // A class that takes all Quorum types and converts them to an MofN quorum, with validation.
  QuorumConverter quorum_converter_;

  // A utility for calculating dynamic timeouts for replies.
  bftEngine::impl::DynamicUpperLimitWithSimpleFilter<uint64_t> expected_commit_time_ms_;

  Metrics metrics_;

  // Transaction RSA signer
  std::optional<bftEngine::impl::RSASigner> transaction_signer_;

  // 1 second
  static constexpr int64_t MAX_VALUE_NANOSECONDS = 1000 * 1000 * 1000;
  struct Recorders {
    using Recorder = concord::diagnostics::Recorder;
    Recorders(ClientId client_id) : component_name_("bft_client_" + client_id.val) {
      auto& registrar = concord::diagnostics::RegistrarSingleton::getInstance();
      registrar.perf.registerComponent(component_name_, {sign_duration});
    }
    DEFINE_SHARED_RECORDER(sign_duration, 1, MAX_VALUE_NANOSECONDS, 3, concord::diagnostics::Unit::NANOSECONDS);

    ~Recorders() {
      auto& registrar = concord::diagnostics::RegistrarSingleton::getInstance();
      registrar.perf.unRegisterComponent(component_name_);
    }

   private:
    std::string component_name_;
  };

  std::unique_ptr<Recorders> histograms_;
};

}  // namespace bft::client
