cmake_minimum_required(VERSION 3.16)
project(zdb_standalone CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Core sources (standalone)
set(ZDB_CORE_SOURCES
    src/repl.cpp
    src/command/debug.cpp
    src/command/regs.cpp
    src/command/load.cpp
    src/command/status.cpp
    src/command/vars.cpp
    src/elf_loader.cpp
    src/backend/mock_backend.cpp
)

add_library(zdb_core STATIC ${ZDB_CORE_SOURCES})
target_include_directories(zdb_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(zdb src/main.cpp)
target_link_libraries(zdb PRIVATE zdb_core)

if (WIN32)
  target_compile_definitions(zdb_core PUBLIC ZDB_PLATFORM_WINDOWS=1)
elseif(UNIX)
  target_compile_definitions(zdb_core PUBLIC ZDB_PLATFORM_LINUX=1)
endif()

