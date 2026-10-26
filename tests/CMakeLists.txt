# One test binary: Thunder's cases plus the core's (bt_core_test_cases from core/).
add_executable(bt_tests
  test_zside_types.cpp
  test_zside_replay.cpp
  test_zside_quirks.cpp
  test_zside_orchard.cpp)
target_link_libraries(bt_tests PRIVATE bt_test_harness bt_core_test_cases zside_core bt_core)
target_compile_definitions(bt_tests PRIVATE BT_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
add_test(NAME bt_tests COMMAND bt_tests)
if(BT_WITH_NET)
  # The node's P2P hardening, over QUIC on loopback.
  target_sources(bt_tests PRIVATE test_zside_node.cpp)
  target_link_libraries(bt_tests PRIVATE zside_node bt_net)
endif()
