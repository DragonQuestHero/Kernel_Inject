#include "CRT/Ntddk.hpp"
#include "DLL_Inject.h"


DLL_Inject *_DLL_Inject;

void DriverUnload(PDRIVER_OBJECT drive_object)
{
	DbgPrint("Unload Over!\n");
	_DLL_Inject->UnRegister_Load_Image();
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drive_object, PUNICODE_STRING path)
{
	drive_object->DriverUnload = DriverUnload;

	_DLL_Inject = new DLL_Inject();
	_DLL_Inject->Register_Load_Image();



	return STATUS_SUCCESS;
}