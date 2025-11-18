// Minimal standalone configuration for zdb (decoupled from SuBase)
#pragma once

// Platform detection
#if defined(_WIN32) || defined(_WIN64)
#  define ZDB_PLATFORM_WINDOWS 1
#else
#  define ZDB_PLATFORM_WINDOWS 0
#endif

#if defined(__linux__)
#  define ZDB_PLATFORM_LINUX 1
#else
#  define ZDB_PLATFORM_LINUX 0
#endif

// Emulate DEVPORT(x) macro usage in sources
#define DEVPORT(x) ZDB_PLATFORM_##x

// Version string replacement
#ifndef SUBASE_VERSION_STRING
#  define SUBASE_VERSION_STRING "zdb-standalone"
#endif

// Minimal MAKE_CSU_ID replacement (no-op encoding)
#ifndef MAKE_CSU_ID
#  define MAKE_CSU_ID(a,b,c) ((unsigned)(c))
#endif

// When building standalone, we don’t have SuBase driver/constants.
// Any code choosing between SRAM/DRAM can ignore and default to DRAM.
// If needed later, define address ranges here.
// #define ZDR_ITCM_BASE_ADDR 0x00000000ULL
// #define ZDR_ITCM_SIZE      0x00000000ULL
// ...