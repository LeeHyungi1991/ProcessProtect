#pragma once
#include <ntifs.h>
#include <fltkernel.h>
//#pragma comment(lib, "fltMgr.lib")
//============================================//
//=========== Undocumented API ===============//
//============================================//

typedef NTSTATUS(*NtQueryInformationProcess_t)(
	_In_	HANDLE					ProcessHandle,
	_Out_	PROCESSINFOCLASS		ProcessInformationClass,
	_In_	PVOID					ProcessInformation,
	_Out_	ULONG					ProcessInformationLength,
	_Out_	PULONG					ReturnLength
	);

//============================================//
//======= Structure & Global Variable ========//
//============================================//

typedef struct _IMPORT_OFFSET
{
	int			UniqueProcessid_off;
	int			ActiveProcessLinks_off;
	int			ImageFileName_off;
	int			PEB_off;
}IMPORT_OFFSET;

HANDLE hPid;
IMPORT_OFFSET iOffset;
const char szSystem[] = "System";
const wchar_t szNtQueryInformationProcess[] = L"NtQueryInformationProcess";