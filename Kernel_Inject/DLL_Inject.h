#pragma once
#include "CRT/Ntddk.hpp"
#include "CRT/NtSysAPI_Func.hpp"
#include "Process.hpp"
#include "Blackbone.h"
#include "Get_SSDT.hpp"

class DLL_Inject
{
public:
	DLL_Inject()
	{
		_This = this;
		RTL_OSVERSIONINFOW Version = { 0 };
		Version.dwOSVersionInfoSize = sizeof(Version);
		RtlGetVersion(&Version);
		if (Version.dwMajorVersion == 6)
		{
			if (Version.dwMinorVersion == 0)
			{
				AddressCreationLock_Offset = 0x0178;
			}
			if (Version.dwMinorVersion == 1)
			{
				AddressCreationLock_Offset = 0x0218;
			}
		}
		else
		{
			AddressCreationLock_Offset = 0x0368;
		}
	}
	~DLL_Inject() = default;
public:
	bool Register_Load_Image();
	bool UnRegister_Load_Image();
private:
	static void Load_Image(
		_In_ PUNICODE_STRING FullImageName,
		_In_ HANDLE ProcessId,
		_In_ PIMAGE_INFO ImageInfo
		);
	static void Write_Process_Memory();
private:
	static DLL_Inject *_This;
	void *LdrLoadDll_Func = nullptr;
	void *LdrGetProcedureAddressForCaller_Func = nullptr;
	ULONG64 AddressCreationLock_Offset = 0;
};

