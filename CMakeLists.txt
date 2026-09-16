cmake_minimum_required(VERSION 3.16)
project(pulsaros-netstack C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk>=22.11)

add_library(netstack STATIC
  src/config.c src/dpdk_port.c src/graph.c src/runtime.c src/neighbour.c
  src/nodes/drop.c src/nodes/ingress.c src/nodes/icmp.c
  src/nodes/register.c src/nodes/tx.c)
target_include_directories(netstack PUBLIC include)
target_link_libraries(netstack PUBLIC PkgConfig::DPDK)
target_compile_options(netstack PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_executable(netstack-dp src/main.c)
target_link_libraries(netstack-dp PRIVATE netstack)

include(CTest)
if(BUILD_TESTING)
  add_executable(test-netstack tests/test_netstack.c)
  target_link_libraries(test-netstack PRIVATE netstack)
  target_compile_options(test-netstack PRIVATE -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
  add_test(NAME netstack-packets COMMAND test-netstack)
  add_executable(test-config tests/test_config.c)
  target_link_libraries(test-config PRIVATE netstack)
  target_compile_options(test-config PRIVATE -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
  add_test(NAME netstack-config COMMAND test-config)
endif()
