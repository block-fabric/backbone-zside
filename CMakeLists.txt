cmake_minimum_required(VERSION 3.22)
project(backbone_zside VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

# The shared engine (git submodule ../backbone-core at core/): defines the BT_* options,
# finds the dependencies (core/depends/built/<host> when present) and the targets
# bt_core, bt_net, bt_test_harness and bt_core_test_cases. It also sets
# -ffp-contract=off for every consumer of bt_core (consensus f64 math).
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/core/CMakeLists.txt")
  message(FATAL_ERROR "core/ is empty: run `git submodule update --init`")
endif()
# Our name and version (core's bt/agent.h): in our QUIC certificate's CN, "<Name> <version> (Backbone drop-in)",
# the one place a peer can read it (the protocol has no user-agent field), and in the startup log.
set(BT_AGENT_NAME "zSide")
set(BT_AGENT_VERSION "${PROJECT_VERSION}")
add_subdirectory(core)

add_subdirectory(chains/zside)

# Our app of zSide (doc/app.md): zside-app, the node (thunder-orchard, unchanged) with our interface; and its pages as a
# pack for the unified wallet (target zside-app-pack). Needs WebKitGTK (Linux) or WebView2 (Windows), npm, and the
# sidechain template's repository (BT_KIT_DIR) at the commit of app/kit.commit.
option(BT_BUILD_APP "Build zside-app" OFF)
if(BT_BUILD_APP)
  include(core/cmake/BtDesktopApp.cmake)
  bt_desktop_app(zside-app STEM zside NAME ${BT_AGENT_NAME} VERSION ${BT_AGENT_VERSION}
                 CHAIN ${CMAKE_SOURCE_DIR}/app/chain MANIFEST ${CMAKE_SOURCE_DIR}/app/manifest.json
                 KIT_COMMIT_FILE ${CMAKE_SOURCE_DIR}/app/kit.commit MAIN ${CMAKE_SOURCE_DIR}/chains/zside/app/main.cpp NODE_TARGET thunder-orchard)
endif()

if(BT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
