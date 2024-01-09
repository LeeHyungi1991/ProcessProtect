#pragma once
#include "offset.h"
#include <stdio.h>
#include <string.h>

#define PROCESS_TERMINATE       0x0001	// TerminateProcess
#define PROCESS_VM_OPERATION    0x0008	// VirtualProtect, WriteProcessMemory
#define PROCESS_VM_READ         0x0010	// ReadProcessMemory
#define PROCESS_VM_WRITE        0x0020	// WriteProcessMemory

#define SOURCE "webmail_secure_agent.exe"



//============================================//
//======= Pre&Post Callback Functions ========//
//============================================//
int CompreFilename(const wchar_t* FileName, int Length, char target[])
{
	if (FileName && Length > 0)
	{
		size_t len = strlen(target);
		int i;
		for (i = 0; i < len; ++i)
		{
			if (FileName[Length - 1 - i] != target[len - 1 - i])
			{
				return 0;
			}
		}
		return 1;
	}
	return 0;
}

int CompreFilenameWithLength(const wchar_t* FileName, int Length, char target[], size_t length)
{
	if (FileName && Length > 0)
	{		
		int i;
		for (i = 0; i < length; ++i)
		{
			if (FileName[Length - 1 - i] != target[length - 1 - i])
			{
				return 0;
			}
		}
		return 1;
	}
	return 0;
}

int CompreFilenameWrap(const UNICODE_STRING FileName, char target[])
{
	return CompreFilename(FileName.Buffer, FileName.Length / sizeof(wchar_t), target);
}
int CompreFilenameWrapWithLength(const UNICODE_STRING FileName, char target[], size_t length)
{
	return CompreFilenameWithLength(FileName.Buffer, FileName.Length / sizeof(wchar_t), target, length);
}

inline OB_PREOP_CALLBACK_STATUS
PreCallback(
	PVOID RegistrationContext, 
	POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{	
	UNREFERENCED_PARAMETER(RegistrationContext);					
	if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
	{	
		unsigned long mask = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;						
		if (mask & PROCESS_TERMINATE) // || mask & PROCESS_VM_OPERATION || mask & PROCESS_VM_READ || mask & PROCESS_VM_WRITE
		{
			if (mask == 12800 || mask == 2097151) {
				return;
			}
			PEPROCESS pEproc = (PEPROCESS)pOperationInformation->Object;
			PUNICODE_STRING pname = { 0, };
			NTSTATUS status = SeLocateProcessImageName(pEproc, &pname);
			if (NT_SUCCESS(status))
			{
				if (CompreFilenameWrap(*pname, SOURCE))
				{
					pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				}
			}
		}			
	}
	return OB_PREOP_SUCCESS;
}

inline void PostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(pOperationInformation);	
}