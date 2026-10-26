# zSide (eCash slot 98) rule module and binaries.

# The reference Orchard crates (orchard 0.14.0, halo2_proofs 0.3.2: the versions thunder-orchard
# b225827 links) behind a C ABI, built from rust/ with the pinned Cargo.lock, offline, from the
# vendored sources (rust/fetch-vendor.sh fills rust/vendor and checks it against VENDOR.sha256).
find_program(CARGO cargo HINTS $ENV{HOME}/.cargo/bin REQUIRED)
set(ZS_RUST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../rust)
set(ZS_RUST_TARGET_DIR ${CMAKE_BINARY_DIR}/rust-target)
if(CMAKE_CROSSCOMPILING AND WIN32)
  set(ZS_RUST_TRIPLE x86_64-pc-windows-gnu)
  set(ZS_RUST_LIB ${ZS_RUST_TARGET_DIR}/${ZS_RUST_TRIPLE}/release/libzside_orchard_ffi.a)
  set(ZS_RUST_TARGET_ARG --target ${ZS_RUST_TRIPLE})
else()
  set(ZS_RUST_LIB ${ZS_RUST_TARGET_DIR}/release/libzside_orchard_ffi.a)
  set(ZS_RUST_TARGET_ARG)
endif()
file(GLOB ZS_RUST_SRCS ${ZS_RUST_DIR}/zside_orchard_ffi/src/*.rs)
add_custom_command(
  OUTPUT ${ZS_RUST_LIB}
  COMMAND ${CMAKE_COMMAND} -E env CARGO_TARGET_DIR=${ZS_RUST_TARGET_DIR}
          ${CARGO} build --release --locked --offline -j 4 ${ZS_RUST_TARGET_ARG}
          --manifest-path ${ZS_RUST_DIR}/zside_orchard_ffi/Cargo.toml
  DEPENDS ${ZS_RUST_SRCS} ${ZS_RUST_DIR}/zside_orchard_ffi/Cargo.toml ${ZS_RUST_DIR}/zside_orchard_ffi/Cargo.lock
  WORKING_DIRECTORY ${ZS_RUST_DIR}
  COMMENT "cargo build zside_orchard_ffi (orchard 0.14.0)"
  VERBATIM)
add_custom_target(zside_orchard_ffi_build DEPENDS ${ZS_RUST_LIB})
add_library(zside_orchard_ffi STATIC IMPORTED GLOBAL)
set_target_properties(zside_orchard_ffi PROPERTIES IMPORTED_LOCATION ${ZS_RUST_LIB})
add_dependencies(zside_orchard_ffi zside_orchard_ffi_build)
if(WIN32)
  set_property(TARGET zside_orchard_ffi PROPERTY INTERFACE_LINK_LIBRARIES ws2_32 userenv ntdll bcrypt)
else()
  set_property(TARGET zside_orchard_ffi PROPERTY INTERFACE_LINK_LIBRARIES pthread dl m)
endif()

add_library(zside_core STATIC
  src/types.cpp
  src/state.cpp
  src/betanet_fixture.cpp
  src/side_tips.cpp)
target_include_directories(zside_core PUBLIC include)
target_link_libraries(zside_core PUBLIC bt_core zside_orchard_ffi)
target_sources(zside_core PRIVATE src/net.cpp src/archive.cpp src/json.cpp)

if(BT_WITH_NET)
  add_library(zside_node STATIC src/node.cpp src/wallet.cpp src/app.cpp src/appui.cpp)
  target_link_libraries(zside_node PUBLIC zside_core bt_net bt_appui)
  # Their release binaries: thunder-orchard (thunder_orchard_app) and thunder-orchard-cli.
  add_executable(thunder-orchard src/main.cpp)
  target_link_libraries(thunder-orchard PRIVATE zside_node)
  add_executable(thunder-orchard-cli src/cli.cpp)
  target_link_libraries(thunder-orchard-cli PRIVATE bt_core)
  # Fetch full blocks from public betanet peers over their QUIC protocol (client only).
  add_executable(zside-fetch-blocks tools/fetch_blocks.cpp)
  target_link_libraries(zside-fetch-blocks PRIVATE zside_core bt_net)
endif()
