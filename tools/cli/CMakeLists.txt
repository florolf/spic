# SPDX-FileCopyrightText: 2025 Florian Larysch <fl@n621.de>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent OR CC0-1.0

cmake_minimum_required(VERSION 3.1.0...3.10 FATAL_ERROR)
project(spic LANGUAGES C)

option(SANITIZE "build with sanitizers enabled")

add_compile_options(
	-Wall
	-Wextra
	-Wshadow
	-Wno-unused-parameter
	-Wmissing-noreturn
	-Wmissing-prototypes
	-Wstrict-prototypes
)

if(SANITIZE)
	add_compile_options(-fsanitize=undefined -fsanitize=address -fsanitize=leak)
	link_libraries(-fsanitize=address -fsanitize=undefined -fsanitize=leak)
endif()

find_package(PkgConfig REQUIRED)
pkg_search_module(CRYPTO REQUIRED libcrypto)

add_executable(spic-check
	../../provider/openssl.c
	../../spic.c
	main.c
)

target_link_libraries(spic-check ${CRYPTO_LIBRARIES})
target_include_directories(spic-check PRIVATE ${PROJECT_SOURCE_DIR}/../.. ${CRYPTO_INCLUDE_DIRS})

