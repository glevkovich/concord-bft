project (bftclient LANGUAGES CXX)

add_library(bftclient_new STATIC
  src/bft_client.cpp
  src/msg_receiver.cpp
  src/matcher.cpp
  src/quorums.cpp
  ../bftengine/src/bftengine/Crypto.cpp
)

find_package(cryptopp REQUIRED)
target_include_directories(corebft PUBLIC ${CRYPTOPP_INCLUDE_DIRS})

target_include_directories(bftclient_new PUBLIC include)
target_include_directories(bftclient_new PUBLIC src)
target_include_directories(bftclient_new PUBLIC ../bftengine/src)
target_include_directories(bftclient_new PUBLIC ../threshsign/include)
target_include_directories(bftclient_new PUBLIC ../diagnostics/include)
target_link_libraries(bftclient_new PUBLIC bftcommunication bftheaders)

if (BUILD_TESTING)
    add_subdirectory(test)
endif()
