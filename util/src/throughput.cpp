// Concord
//
// Copyright (c) 2018-2020 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").
// You may not use this product except in compliance with the Apache 2.0
// License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#include "throughput.hpp"

namespace concord::util {
//////////////////////////////////////////////////////////////////////////////
// Throughput member functions
//////////////////////////////////////////////////////////////////////////////
void Throughput::start() {
  LOG_INFO(GL, "xxx " << name_ << " start");
  started_ = true;
  overallStats_.reset();
  if (numReportsPerWindow_ > 0ul) {
    currentWindowStats_.reset();
  }
}

bool Throughput::report(uint64_t itemsProcessed, bool triggerCalcThroughput) {
  ConcordAssert(started_);

  ++reportsCounter_;
  overallStats_.results_.numProcessedItems_ += itemsProcessed;
  LOG_INFO(GL,
           "xxx " << name_ << " report"
                  << KVLOG(reportsCounter_, itemsProcessed, overallStats_.results_.numProcessedItems_));
  if (numReportsPerWindow_ > 0ul) {
    currentWindowStats_.results_.numProcessedItems_ += itemsProcessed;
    LOG_INFO(GL, "xxx " << name_ << " report" << KVLOG(currentWindowStats_.results_.numProcessedItems_));
    if (triggerCalcThroughput || ((reportsCounter_ % numReportsPerWindow_) == 0ul)) {
      // Calculate throughput every numReportsPerWindow_ reports
      previousWindowStats_ = currentWindowStats_;
      previousWindowIndex_ = (reportsCounter_ - 1) / numReportsPerWindow_;
      currentWindowStats_.reset();
      previousWindowStats_.calcThroughput();
      overallStats_.calcThroughput();
      prevWinCalculated_ = true;
      LOG_INFO(GL, "xxx " << name_ << " report" << KVLOG(previousWindowIndex_, prevWinCalculated_));
      return true;
    }
  }

  return false;
}

void Throughput::pause() {
  ConcordAssert(started_);
  LOG_INFO(GL, "xxx " << name_ << " pause");
  overallStats_.durationDT_.pause();
  currentWindowStats_.durationDT_.pause();
}

void Throughput::resume() {
  ConcordAssert(started_);
  LOG_INFO(GL, "xxx " << name_ << " resume");
  overallStats_.durationDT_.start();
  currentWindowStats_.durationDT_.start();
}

const Throughput::Results& Throughput::getOverallResults() {
  LOG_INFO(GL, "xxx " << name_ << " getOverallResults" << KVLOG(prevWinCalculated_));
  if (!prevWinCalculated_) {
    ConcordAssert(started_);
    overallStats_.calcThroughput();
  }
  return overallStats_.results_;
}

const Throughput::Results& Throughput::getPrevWinResults() const {
  ConcordAssert(prevWinCalculated_);
  LOG_INFO(GL, "xxx " << name_ << " getPrevWinResults");
  return previousWindowStats_.results_;
}

uint64_t Throughput::getPrevWinIndex() const {
  ConcordAssert(prevWinCalculated_);
  LOG_INFO(GL, "xxx " << name_ << " getPrevWinIndex" << KVLOG(previousWindowIndex_));
  return previousWindowIndex_;
}

//////////////////////////////////////////////////////////////////////////////
// Throughput::Stats member functions
//////////////////////////////////////////////////////////////////////////////

void Throughput::Stats::reset() {
  results_.numProcessedItems_ = 0ull;
  results_.throughput_ = 0ull;
  durationDT_.reset("durationDT_");
  durationDT_.start();
}

void Throughput::Stats::calcThroughput() {
  results_.elapsedTimeMillisec_ = durationDT_.durationMilli();
  results_.throughput_ = static_cast<uint64_t>((1000 * results_.numProcessedItems_) / results_.elapsedTimeMillisec_);
  LOG_INFO(GL,
           "xxx calcThroughput" << KVLOG(results_.elapsedTimeMillisec_,
                                         results_.throughput_,
                                         results_.numProcessedItems_,
                                         results_.elapsedTimeMillisec_));
}

}  // namespace concord::util
