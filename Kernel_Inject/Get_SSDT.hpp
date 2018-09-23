#pragma once
#include "CRT/Ntddk.hpp"
#include "CRT/NtSysAPI_Func.hpp"

class Get_SSDT
{
public:
	Get_SSDT()
	{
		GetKeServiceDescriptorTableAddrX64();
	}
	~Get_SSDT() = default;
public:
	ULONG64 GetSSDTFuncCurAddrByIndex(ULONG index)
	{
		LONG dwtmp = 0;
		ULONGLONG addr = 0;
		PULONG ServiceTableBase = NULL;
		ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
		dwtmp = ServiceTableBase[index];
		dwtmp = dwtmp >> 4;
		addr = ((LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase);//&0xFFFFFFF0;
		return addr;
	}

	KIRQL WPOFFx64()
	{
		KIRQL irql = KeRaiseIrqlToDpcLevel();
		UINT64 cr0 = __readcr0();
		cr0 &= 0xfffffffffffeffff;
		__writecr0(cr0);
		_disable();
		return irql;
	}

	void WPONx64(KIRQL irql)
	{
		UINT64 cr0 = __readcr0();
		cr0 |= 0x10000;
		_enable();
		__writecr0(cr0);
		KeLowerIrql(irql);
	}
public:
	PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable = nullptr;
private:
	void GetKeServiceDescriptorTableAddrX64()
	{
		PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
		PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
		PUCHAR i = NULL;
		UCHAR b1 = 0, b2 = 0, b3 = 0;
		ULONGLONG templong = 0;
		ULONGLONG addr = 0;
		for (i = StartSearchAddress; i < EndSearchAddress; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
			{
				b1 = *(i);
				b2 = *(i + 1);
				b3 = *(i + 2);
				if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
				{
					memcpy(&templong, i + 3, 4);
					//核心部分  
					//kd> db fffff800`03e8b772  
					//fffff800`03e8b772  4c 8d 15 c7 20 23 00 4c-8d 1d 00 21 23 00 f7 83  L... #.L...!#...  
					//templong = 002320c7 ,i = 03e8b772, 7为指令长度  
					addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
					break;
				}
			}
		}
		KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)addr;
	}
};

