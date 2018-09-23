#pragma once
#include "Ntddk.hpp"

#define Tager 'OCK'
#ifdef _AMD64_
static void *operator new(size_t lBlockSize)
{
	return ExAllocatePoolWithTag(NonPagedPool, lBlockSize, Tager);
}

static void operator delete(void *p)
{
	if (p == nullptr)
	{
		return;
	}
	ExFreePoolWithTag(p, Tager);
}
#else
static void * __CRTDECL operator new(size_t lBlockSize)
{
	return ExAllocatePoolWithTag(NonPagedPool, lBlockSize, Tager);
}

static void __CRTDECL operator delete(void *p)
{
	if (!p)
	{
		return;
	}
	ExFreePoolWithTag(p, Tager);
}
#endif