// Concord
//
// Copyright (c) 2018 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").
// You may not use this product except in compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to the
// terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.

#include "threshsign/Configuration.h"

#include "TestThresholdBls.h"

#include <map>
#include <set>
#include <vector>
#include <string>
#include <cassert>
#include <memory>
#include <stdexcept>
#include <inttypes.h>

#include "Logger.hpp"
#include "Utils.h"
#include "Timer.h"
#include "XAssert.h"

#include "threshsign/bls/relic/Library.h"
#include "threshsign/bls/relic/BlsPublicParameters.h"

#include "app/RelicMain.h"

#include "histogram.hpp"
#include "misc.hpp"

concordUtils::Histogram hg;
using namespace std;
using namespace BLS::Relic;

#define KB 1024
#define MB KB* KB

int RelicAppMain(const Library& lib, const std::vector<std::string>& args) {
  (void)args;
  (void)lib;

  //    std::vector<std::pair<int, int>> nk;
  //	for(size_t i = 1; i <= 301; i += 1) {
  //	    nk.push_back(std::pair<int, int>(i, i));
  //	}

  BLS::Relic::BlsPublicParameters params(BLS::Relic::PublicParametersFactory::getWhatever());

  char* msg = new char[1048576 * 32];

  using Clock = std::chrono::system_clock;
  using Duration = Clock::duration;
  std::cout << Duration::period::num << " , " << Duration::period::den << '\n';

  std::vector<int> sizes = {
      1, 32, 512, 1 * KB, 64 * KB, 128 * KB, 512 * KB, 1 * MB, 2 * MB, 4 * MB, 8 * MB, 16 * MB, 32 * MB};
  for (bool multisig : {false}) {
    for (auto i : sizes) {
      LOG_INFO(BLS_LOG, "============================================== " << KVLOG(multisig, i));
      ThresholdBlsTest t(params, 1, 1, multisig);
      hg.Clear();
      for (int ii = 0; ii < 100; ++ii) {
        t.generateKeys();
        t.test(reinterpret_cast<const unsigned char*>(msg), static_cast<int>(i));
      }
      std::cout << "size " << i << ":" << std::endl << hg.ToString() << std::endl << std::flush;
    }
  }

  delete[] msg;
  return 0;
}
