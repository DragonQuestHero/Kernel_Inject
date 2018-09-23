#pragma once
#include "CRT/CRTCPP.hpp"
#include "CRT/NtSysAPI_Func.hpp"



namespace CG
{
	class Process
	{
	public:
		Process() = default;
		~Process() = default;
	public:
		bool Get_Process_EProcess(HANDLE ProcessId, PEPROCESS *Process_Struct)
		{
			NTSTATUS status = 0;
			//get eprocess
			status = PsLookupProcessByProcessId(ProcessId, Process_Struct);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("PsLookupProcessByProcessId ERROR_CODE:%d\n", status));
				return false;
			}
			ObDereferenceObject(*Process_Struct);
			return true;
		}

		//need closehandle
		bool Get_Process_Handle(HANDLE ProcessId, HANDLE *Process_Handle)
		{
			NTSTATUS status = 0;
			//open process get processhandle
			OBJECT_ATTRIBUTES obj_attributes = { 0 };
			InitializeObjectAttributes(&obj_attributes, 0, 0, 0, 0);
			CLIENT_ID cid = { 0 };
			cid.UniqueProcess = ProcessId;
			status = ZwOpenProcess(Process_Handle, GENERIC_ALL, &obj_attributes, &cid);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("ZwOpenProcess ERROR_CODE:%d\n", status));
				return false;
			}
			return true;
		}

		bool Get_Process_PEB(PEPROCESS Process, PPEB *PEB)
		{
			NTSTATUS status = 0;
			*PEB = PsGetProcessPeb(Process);
			return true;
		}

		//need delete path
		bool Get_Process_Image(HANDLE Process_Handle,UNICODE_STRING *Process_Path)
		{
			NTSTATUS status = 0;
			ULONG Query_Return_Lenght = 0;
			UNICODE_STRING *temp_process_image_name = nullptr;
			FILE_OBJECT *process_image_file_object = nullptr;
			DEVICE_OBJECT *process_image_device_object = nullptr;
			OBJECT_NAME_INFORMATION *process_image_object_name = nullptr;

			//get full image name
			status = ZwQueryInformationProcess(Process_Handle, ProcessImageFileName,
				nullptr, 0, &Query_Return_Lenght);
			temp_process_image_name = (UNICODE_STRING*)new char[Query_Return_Lenght];
			RtlZeroMemory(temp_process_image_name, Query_Return_Lenght);
			//frist call ZwQueryInformationProcess get how long memory for we need
			status = ZwQueryInformationProcess(Process_Handle, ProcessImageFileName,
				temp_process_image_name, Query_Return_Lenght, &Query_Return_Lenght);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("ZwQueryInformationProcess ERROR_CODE:%d\n", status));
				goto Clean;
			}

			//conversion the image path
			status = IoGetDeviceObjectPointer(temp_process_image_name, SYNCHRONIZE,
				&process_image_file_object, &process_image_device_object);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("IoGetDeviceObjectPointer ERROR_CODE:%d\n", status));
				goto Clean;
			}
			status = IoQueryFileDosDeviceName(process_image_file_object, &process_image_object_name);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("IoQueryFileDosDeviceName ERROR_CODE:%d\n", status));
				goto Clean;
			}
			Process_Path->Length = process_image_object_name->Name.Length;
			Process_Path->MaximumLength = process_image_object_name->Name.MaximumLength;
			Process_Path->Buffer = (PWCH)new char[Process_Path->MaximumLength];
			RtlCopyMemory(Process_Path->Buffer,
				process_image_object_name->Name.Buffer, Process_Path->MaximumLength);

			ExFreePool(process_image_object_name);
			delete[] (char*)temp_process_image_name;
			ObDereferenceObject(process_image_file_object);
			return true;
		Clean:
			//we did it but need free memory
			ExFreePool(process_image_object_name);
			delete[](char*)temp_process_image_name;
			ObDereferenceObject(process_image_file_object);
			return false;
		}

		bool Get_Process_Command(HANDLE Process_Handle, PEPROCESS Process,
			PPEB PEB, UNICODE_STRING *CommandLine)
		{
			/*NTSTATUS status = 0;
			ULONG Query_Return_Lenght = 0;

			ULONG_PTR IsWin32Process = 0;
			status = Func_ZwQueryInformationProcess(Process_Handle, ProcessWow64Information,
			&IsWin32Process, sizeof(ULONG_PTR), &Query_Return_Lenght);
			if (!NT_SUCCESS(status))
			{
			KdPrint(("ZwQueryInformationProcess ERROR_CODE:%d\n", status));
			return false;
			}*/

			KAPC_STATE apc_state;
			KeStackAttachProcess(Process, &apc_state);

			//ULONG64 *temp_point = nullptr;
			//if (IsWin32Process == 0)// not running in a WOW64 environment.
			//{
			//	temp_point = (ULONG64*)((char*)PEB + 0x20);
			//}
			//else
			//{
			//	temp_point = (ULONG64*)((char*)PEB + 0x10);
			//}

#ifdef _AMD64_ 
			ULONG64 *temp_point = (ULONG64*)((char*)PEB + 0x20);
#else
			ULONG64 *temp_point = (ULONG64*)((char*)PEB + 0x10);
#endif

			RTL_USER_PROCESS_PARAMETERS *temp_struct = (RTL_USER_PROCESS_PARAMETERS*)*temp_point;

			CommandLine->Buffer = (WCHAR*)new char[temp_struct->CommandLine.MaximumLength];
			CommandLine->Length = temp_struct->CommandLine.Length;
			CommandLine->MaximumLength = temp_struct->CommandLine.MaximumLength;
			RtlCopyMemory(CommandLine->Buffer, temp_struct->CommandLine.Buffer, CommandLine->MaximumLength);

			KeUnstackDetachProcess(&apc_state);

			return true;
		}

		//----------
		bool Get_Process_SID(HANDLE Process_Handle)
		{
			NTSTATUS status = 0;
			ULONG Query_Return_Lenght = 0;
			HANDLE ProcessToken_Handle = nullptr;
			//
			UNICODE_STRING ZwOpenProcessToken_Func_Name;
			RtlInitUnicodeString(&ZwOpenProcessToken_Func_Name, L"ZwOpenProcessToken");
			_ZwOpenProcessToken Func_ZwOpenProcessToken = (_ZwOpenProcessToken)
				MmGetSystemRoutineAddress(&ZwOpenProcessToken_Func_Name);
			if (!Func_ZwOpenProcessToken)
			{
				KdPrint(("Get ZwOpenProcessToken Error\n"));
				goto Clean;
			}
			status = Func_ZwOpenProcessToken(Process_Handle, TOKEN_ALL_ACCESS, &ProcessToken_Handle);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("ZwOpenProcessToken ERROR_CODE:%d\n", status));
				goto Clean;
			}
			CHAR Buffer[200];
			TOKEN_USER *token_user = nullptr;
			UNICODE_STRING SidString;
			Query_Return_Lenght = 0;
			ZwQueryInformationToken(ProcessToken_Handle, TokenUser,
				Buffer, 200, &Query_Return_Lenght);
			//RtlCopySid()
			if (!NT_SUCCESS(status))
			{
				KdPrint(("ZwQueryInformationToken ERROR_CODE:%d\n", status));
				goto Clean;
			}
			token_user = (PTOKEN_USER)Buffer;
			status = RtlConvertSidToUnicodeString(&SidString, token_user->User.Sid, true);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("RtlConvertSidToUnicodeString ERROR_CODE:%d\n", status));
				goto Clean;
			}
			KdPrint(("%wZ\n", SidString));


			RtlFreeUnicodeString(&SidString);
			ZwClose(ProcessToken_Handle);
			return true;
		Clean:
			RtlFreeUnicodeString(&SidString);
			ZwClose(ProcessToken_Handle);
			return false;
		}

		bool Get_Process_Create_Time(HANDLE Process_Handle)
		{
			NTSTATUS status = 0;
			ULONG Query_Return_Lenght = 0;

			KERNEL_USER_TIMES temp_time = { 0 };
			ZwQueryInformationProcess(Process_Handle, ProcessTimes,
				&temp_time, sizeof(KERNEL_USER_TIMES), &Query_Return_Lenght);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("ZwQueryInformationProcess ERROR_CODE:%d\n", status));
				return false;
			}

			KdPrint(("%d\n", temp_time.CreateTime.QuadPart));


		}
	private:
		_PsGetProcessPeb PsGetProcessPeb = nullptr;
	};
}