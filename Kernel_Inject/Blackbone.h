#pragma once
#include "CRT/Ntddk.hpp"
#include "CRT/NtSysAPI_Func.hpp"


PVOID BBGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord);
