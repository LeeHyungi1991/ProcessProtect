#include "stdio.h"

#define SERVICE_EXE "services.exe"
#define SVCHOST_EXE "svchost.exe"
#define TASKMRG_EXE "taskmgr.exe"
#define WINREG_EXE "winreg.exe"
#define REGEDIT_EXE "regedit.exe"

typedef struct _GLOBAL_CONTEXT {
	PDRIVER_OBJECT DriverObject;
	UNICODE_STRING Altitude;
	LARGE_INTEGER Cookie;
} GLOBAL_CONTEXT, * PGLOBAL_CONTEXT;
GLOBAL_CONTEXT g_GlobalContext = { 0 };

UNICODE_STRING g_PolicyKeyArray[] = {
	RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\webmail_secure_agent.exe"),
	RTL_CONSTANT_STRING(L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Webmail secure agent"),
	RTL_CONSTANT_STRING(L"Software\\Webmail secure agent"),
	RTL_CONSTANT_STRING(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32"),	
	RTL_CONSTANT_STRING(L"System\\ControlSet001\\Services\\ProcessProtect"),	
	RTL_CONSTANT_STRING(L"System\\ControlSet001\\Services\\ProcessProtect\\Instances"),	
	RTL_CONSTANT_STRING(L"System\\ControlSet001\\Services\\ProcessProtect\\Instances\\ProcessProtect Instance"),
};
ULONG g_PolicyKeyCount = sizeof(g_PolicyKeyArray) / sizeof(UNICODE_STRING);


BOOLEAN
CheckProcess(VOID) {
	PEPROCESS  Process;

	Process = PsGetCurrentProcess();
	PUNICODE_STRING pname = { 0, };
	NTSTATUS status = SeLocateProcessImageName(Process, &pname);

	if (!NT_SUCCESS(status)) {
		return TRUE;
	}
	/*if (CompreFilenameWrap(*pname, SERVICE_EXE)) {		
		return TRUE;
	}*/

	if (CompreFilenameWrap(*pname, SVCHOST_EXE)) {		
		return TRUE;
	}

	if (CompreFilenameWrap(*pname, SOURCE)) {
		return TRUE;
	}
		
	return FALSE;
}


BOOLEAN CheckPolicy(PUNICODE_STRING KeyFullPath) {

	BOOLEAN Matched = FALSE;
	ULONG Idx;

	for (Idx = 0; Idx < g_PolicyKeyCount; Idx++) {
		if (RtlEqualUnicodeString(KeyFullPath, &g_PolicyKeyArray[Idx], TRUE)) {
			Matched = TRUE;
			break;
		}
	}

	if (Matched) {
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[ RegMonitor ] pid(%x) and tid(%x) Block %wZ\n", PsGetCurrentProcessId(), PsGetCurrentThreadId(), KeyFullPath);
	}	

	return Matched;
}


NTSTATUS RegPreDeleteKey(PVOID RootObject, PUNICODE_STRING CompleteName)
{

	//PUNICODE_STRING RootObjectName;
	//ULONG_PTR RootObjectID;
	//BOOLEAN Matched = FALSE;
	//NTSTATUS Status;
	//UNICODE_STRING KeyPath = { 0 };

	// CompleteName can have a absolute path or relative path.
	// That's why we should do more work.	
	UNREFERENCED_PARAMETER(RootObject);
	BOOLEAN Matched = CheckPolicy(CompleteName);		
	return Matched;
}


NTSTATUS RegistryFilterCallback(
	IN PVOID               CallbackContext,
	IN PVOID               Argument1,
	IN PVOID               Argument2
) {
	NTSTATUS Status = STATUS_SUCCESS;
	REG_NOTIFY_CLASS NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

	UNREFERENCED_PARAMETER(CallbackContext);

	if (CheckProcess()) {
		return STATUS_SUCCESS;
	}

	if (RegNtPreCreateKeyEx == NotifyClass || RegNtPreOpenKeyEx == NotifyClass)
	{
		PREG_CREATE_KEY_INFORMATION RegInformation = (PREG_CREATE_KEY_INFORMATION)Argument2;

		if (RegPreDeleteKey(RegInformation->RootObject, RegInformation->CompleteName))
		{
			ACCESS_MASK mask = RegInformation->DesiredAccess;
			if (mask & DELETE || mask & WRITE_DAC || mask & WRITE_OWNER) {
				DbgPrintEx(DPFLTR_ACPI_ID, 0, "[ RegMonitor ] Prevent Opening Handle\n");
				Status = STATUS_ACCESS_DENIED;			
			}			
		}					
	}

	return Status;
}


NTSTATUS InstallRegMonitor(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS Status = STATUS_SUCCESS;
	RtlInitUnicodeString(&g_GlobalContext.Altitude, L"140831");
	g_GlobalContext.DriverObject = DriverObject;

	if (!NT_SUCCESS(Status = CmRegisterCallbackEx(
		RegistryFilterCallback,
		&g_GlobalContext.Altitude,
		DriverObject,
		&g_GlobalContext,
		&g_GlobalContext.Cookie,
		NULL
	))) {
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[ RegMonitor ] [ ERROR ] CmRegisterCallbackEx Failed : (%x)\n", Status);		
		return Status;
	}
	else {
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[ RegMonitor ] [ SUCCESS ] CmRegisterCallbackEx Success\n");
	}

	return STATUS_SUCCESS;
}


NTSTATUS UnInstallRegMonitor()
{
	NTSTATUS Status;

	if (!NT_SUCCESS(Status = CmUnRegisterCallback(g_GlobalContext.Cookie))) {
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[ RegMonitor ] [ ERROR ] CmUnRegisterCallback Failed (%x)\n", Status);		
		return Status;
	}
	else {
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[ RegMonitor ] [ SUCCESS ] CmUnRegisterCallback Success\n");		
	}
	return STATUS_SUCCESS;
}