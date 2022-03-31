#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define OXORANY_DISABLE_OBFUSCATION

typedef unsigned long ulong_t;

// system headers

#include <windows.h>
#include <winternl.h>
#include <vector>
#include <cstdint>
#include <functional>
#include <fstream>
#include <iostream>
#include <random>
#include <conio.h>
#include <tlhelp32.h>

// resources

#include "resources/phymemx.hpp"

// implementation

#include "utils/misc/shared.hpp"
#include "utils/misc/oxorany.hpp"
#include "utils/misc/lazy_importer.hpp"
#include "utils/misc/singleton.hpp"
#include "utils/misc/shellcode.hpp"

#include "utils/util/util.hpp"
#include "utils/io/io.hpp"
#include "utils/service/service.hpp"
#include "utils/kernel/kernel.hpp"
#include "utils/phymem/phymem.hpp"

#include "bootstrap/bootstrap.hpp"
#include "executor/executor.hpp"
#include "driver/driver.hpp"