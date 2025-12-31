# SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0

cmake_minimum_required(VERSION 3.1.0...3.10 FATAL_ERROR)
project(spic-unittest LANGUAGES C)

find_package(PkgConfig REQUIRED)

pkg_search_module(CMOCKA REQUIRED cmocka)

add_compile_options(
	-Wall
	-Wextra
	-Wshadow
	-Wno-unused-parameter
	-Wmissing-noreturn
	-Wmissing-prototypes
	-Wstrict-prototypes

	-fsanitize=undefined
	-fsanitize=address
)

link_libraries(-fsanitize=address -fsanitize=undefined)

add_compile_definitions(TESTING SPIC_INTERNAL_TESTEXPOSE SPIC_EXPOSE_BARE)

add_executable(b64 b64.c dummy-provider.c ../../spic.c)
target_include_directories(b64 PRIVATE ${PROJECT_SOURCE_DIR}/../.. ${CMOCKA_INCLUDES})
target_link_libraries(b64 PRIVATE ${CMOCKA_LIBRARIES})
add_test(b64 b64)

add_executable(bare bare.c dummy-provider.c ../../spic.c)
target_include_directories(bare PRIVATE ${PROJECT_SOURCE_DIR}/../..  ${CMOCKA_INCLUDES})
target_link_libraries(bare PRIVATE ${CMOCKA_LIBRARIES})
add_test(bare bare)
