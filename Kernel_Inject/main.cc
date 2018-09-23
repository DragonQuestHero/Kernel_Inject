#include "CRT/Ntddk.hpp"
#include "DLL_Inject.h"




void DriverUnload(PDRIVER_OBJECT drive_object)
{
	DbgPrint("Unload Over!\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drive_object, PUNICODE_STRING path)
{
	drive_object->DriverUnload = DriverUnload;

	DLL_Inject *_DLL_Inject = new DLL_Inject();
	_DLL_Inject->Register_Load_Image();



	return STATUS_SUCCESS;
}