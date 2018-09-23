#include "DLL_Inject.h"

DLL_Inject *DLL_Inject::_This;

bool DLL_Inject::Register_Load_Image()
{
	NTSTATUS status = PsSetLoadImageNotifyRoutine(DLL_Inject::Load_Image);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("PsSetLoadImageNotifyRoutine:%d", status);
	}
	return false;
}

char shellcode3[14] = { 0 };
KEVENT wait_event;
PEPROCESS Process_Struct;

void DLL_Inject::Write_Process_Memory()
{
	char shellcode[] =
		"\x50\x52\x51" //push rax	push rdx	push rcx
		"\x48\xB8\x11\x11\x11\x11\x11\x11\x11\x11" //mov rax, 0x1111111111111111
		"\x49\x89\xC0" //mov r8, rax
		"\x48\xB8\x11\x11\x11\x11\x11\x11\x11\x11" //mov rax, 0x1111111111111111
		"\x49\x89\xC1" //mov r9,rax
		"\x48\x31\xD2" //xor rdx,rdx
		"\x48\x31\xC9" //xor rcx,rcx
		"\x48\xB8\x11\x11\x11\x11\x11\x11\x11\x11" //mov rax, 0x1111111111111111
		"\xFF\xD0" //call rax
		"\x59\x5A\x58"//pop rax	pop rdx	 pop rcx 51
		"\x4C\x8B\xD1"
		"\xB8\x7E\x01\x00\x00"
		"\x0F\x05"
		"\xC3"; 


	Get_SSDT get_ssdt;
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)get_ssdt.GetSSDTFuncCurAddrByIndex(0x004d);
	_NtReadVirtualMemory NtReadVirtualMemory = (_NtReadVirtualMemory)get_ssdt.GetSSDTFuncCurAddrByIndex(0x003f);
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)get_ssdt.GetSSDTFuncCurAddrByIndex(0x0037);


	HANDLE process_handle;
	NTSTATUS status = ObOpenObjectByPointer(Process_Struct, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS,
		NULL, KernelMode, &process_handle);

	void* shellcode_addr = 0;
	ULONG_PTR shellcode_addr_lenght = 0x1000;
	status = ZwAllocateVirtualMemory(process_handle, &shellcode_addr, NULL,
		&shellcode_addr_lenght, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		return;
	}


	wchar_t shellcode_dll_name[] = L"C:\\d3d11hook.dll";
	status = NtWriteVirtualMemory(process_handle, (void*)((ULONG_PTR)shellcode_addr+0x100), shellcode_dll_name, sizeof(shellcode_dll_name), NULL);
	if (!NT_SUCCESS(status))
	{
		return;
	}


	UNICODE_STRING shellcode_unicode_str;
	shellcode_unicode_str.Length = sizeof(shellcode_dll_name)-2;
	shellcode_unicode_str.MaximumLength = sizeof(shellcode_dll_name);
	shellcode_unicode_str.Buffer = (PWCH)((ULONG_PTR)shellcode_addr + 0x100);
	status = NtWriteVirtualMemory(process_handle, (void*)((ULONG_PTR)shellcode_addr + 0x200), &shellcode_unicode_str, sizeof(UNICODE_STRING), NULL);
	if (!NT_SUCCESS(status))
	{
		return;
	}


	ULONG_PTR temp_handle = 0;
	status = NtWriteVirtualMemory(process_handle, (void*)((ULONG_PTR)shellcode_addr + 0x300), &temp_handle, sizeof(ULONG_PTR), NULL);
	if (!NT_SUCCESS(status))
	{
		return;
	}

	*(ULONG_PTR*)(shellcode + 5) = (ULONG_PTR)((ULONG_PTR)shellcode_addr + 0x200);
	*(ULONG_PTR*)(shellcode + 18) = (ULONG_PTR)((ULONG_PTR)shellcode_addr + 0x300);
	void *test2 = _This->LdrLoadDll_Func;
	*(ULONG_PTR*)(shellcode + 37) = (ULONG_PTR)_This->LdrLoadDll_Func;
	status = NtWriteVirtualMemory(process_handle, shellcode_addr, shellcode, sizeof(shellcode), NULL);
	if (!NT_SUCCESS(status))
	{
		return;
	}

	char shellcode2[] =
		"\x48\xB8\x11\x11\x11\x11\x11\x11\x11\x11" //mov rax, 0x1111111111111111
		"\x50\xC3";
	*(ULONG_PTR*)(shellcode2 + 2) = (ULONG_PTR)shellcode_addr;
	ULONG64 Protect_Size = 5;
	ULONG Old_Protect = 0;
	ULONG Temp_Protect = 0;
	void *test = _This->LdrGetProcedureAddressForCaller_Func;
	status = NtProtectVirtualMemory(process_handle, &test, &Protect_Size,
		PAGE_EXECUTE_READWRITE, &Old_Protect);
	if (!NT_SUCCESS(status))
	{
		return;
	}
	status = NtWriteVirtualMemory(process_handle, _This->LdrGetProcedureAddressForCaller_Func, shellcode2, sizeof(shellcode2), NULL);
	if (!NT_SUCCESS(status))
	{
		return;
	}
	status = NtProtectVirtualMemory(process_handle, &test, &Protect_Size,
		Old_Protect, &Temp_Protect);
	if (!NT_SUCCESS(status))
	{
		return;
	}

	RtlCopyMemory(shellcode3, shellcode2, sizeof(shellcode2));
	ZwClose(process_handle);
	KeSetEvent(&wait_event, 0, TRUE);
}

void DLL_Inject::Load_Image(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
	)
{
	NTSTATUS status;
	if (ProcessId == (HANDLE)0 || ProcessId == (HANDLE)4) return;
	if (ImageInfo->SystemModeImage)return;


	UNICODE_STRING temp_path;
	RtlInitUnicodeString(&temp_path, L"*SYSTEMROOT\\SYSTEM32\\NTDLL.DLL");
	if (!FsRtlIsNameInExpression(&temp_path, FullImageName, true, nullptr))
	{
		return;
	}

	CG::Process process;
	HANDLE process_handle;
	if (!process.Get_Process_EProcess(ProcessId, &Process_Struct))
	{
		return;
	}
	if (process.Get_Process_Handle(ProcessId, &process_handle))
	{
		if (process.Get_Process_Image(process_handle, &temp_path))
		{
			UNICODE_STRING temp_path2;
			RtlInitUnicodeString(&temp_path2, L"*CALC.EXE");//TSLGAME
			if (!FsRtlIsNameInExpression(&temp_path2, &temp_path, true, nullptr))
			{
				delete temp_path.Buffer;
				return;
			}

			DbgBreakPoint();

			KAPC_STATE apc;
			KeStackAttachProcess(Process_Struct, &apc);
			_This->LdrLoadDll_Func = BBGetModuleExport(ImageInfo->ImageBase, "LdrLoadDll");
			_This->LdrGetProcedureAddressForCaller_Func = BBGetModuleExport(ImageInfo->ImageBase, "ZwTestAlert");
			KeUnstackDetachProcess(&apc);

			HANDLE thread_handle;
			PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
				(PKSTART_ROUTINE)Write_Process_Memory, NULL);

			KeInitializeEvent(&wait_event, SynchronizationEvent,//SynchronizationEvent为同步事件  
				FALSE);
			KeWaitForSingleObject(&wait_event, Executive, KernelMode, FALSE, NULL);
			/*ULONG_PTR AddressCreationLock = *(ULONG_PTR*)((ULONG_PTR)Process_Struct + _This->AddressCreationLock_Offset);
			*(ULONG_PTR*)((ULONG_PTR)Process_Struct + _This->AddressCreationLock_Offset) = 0;*/


			delete temp_path.Buffer;
			ZwClose(process_handle);
			//*(ULONG_PTR*)((ULONG_PTR)Process_Struct + _This->AddressCreationLock_Offset) = AddressCreationLock;
		}
	}


}