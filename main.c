#include "common.h"

PVOID hRegistration = NULL;	// 언로드 시, 사용하기 위해 전역변수로 선언
#define SIOCTL_TYPE 40000
#define IOCTL_HELLO\
 CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define AUTHENTICATION_CODE "KXyBI79u+65gTGNk2ZyamN/IOZBcTLN7dmJux5JekW4="

#define MIRROR "mirror.exe"
#define UNINST "uninst_webmail_secure_agent.exe"
#define SYS "ProcessProtect.sys"
#define INF "ProcessProtect.inf"
#define CAT "processprotect.cat"
#define ICO "mail_14377.ico"
#define URL "DIFFSPEC.url"
#define DLL "detector.dll"
#define DB "local_temp_data.db"
#define GEO "GeoLite2-Country.mmdb"

const WCHAR deviceNameBuffer[] = L"\\Device\\MYDEVICE";
const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\MyDevice";
PDEVICE_OBJECT g_MyDevice; // Global pointer to our device object


NTSTATUS Function_IRP_MJ_CREATE(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	DbgPrint("IRP MJ CREATE received.\n");
	return STATUS_SUCCESS;
}


NTSTATUS Function_IRP_MJ_CLOSE(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	DbgPrint("IRP MJ CLOSE received.\n");
	return STATUS_SUCCESS;
}


NTSTATUS Function_IRP_DEVICE_CONTROL(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{	
	UNREFERENCED_PARAMETER(Irp);
	PIO_STACK_LOCATION pIoStackLocation;
	PCHAR welcome = "Hello from kerneland.";
	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;	
	char* pChar;
	pChar = pBuf;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_HELLO:
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "IOCTL HELLO.\n");
		if (strcmp(pChar, AUTHENTICATION_CODE) == 0)
		{
			pDeviceObject->DriverObject->DriverExtension->AddDevice = NULL;
			DbgPrintEx(DPFLTR_ACPI_ID, 0, "AUTHENTICATED!!\n");
		}				
		RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
		RtlCopyMemory(pBuf, welcome, strlen(welcome));

		break;
	}

	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = strlen(welcome);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

/*
# Name  : ObRegExample
# Param : x
# Desc  : OB_CALLBACK, OPERATION_REGISTRATION 구조체 초기화 및 ObRegisterCallbacks 를 이용해 콜백 루틴 등록
*/
NTSTATUS ObRegExample()
{
	OB_CALLBACK_REGISTRATION obRegistration = { 0, };
	OB_OPERATION_REGISTRATION opRegistration = { 0, };

	opRegistration.ObjectType = PsProcessType;
	opRegistration.PreOperation = PreCallback;	// PreOperation 등록
	opRegistration.PostOperation = PostCallback;	// PostOperation 등록
	opRegistration.Operations = OB_OPERATION_HANDLE_CREATE;	// Create 또는 Open 시 동작

	obRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	obRegistration.OperationRegistrationCount = 1;
	obRegistration.OperationRegistration = &opRegistration;
	RtlInitUnicodeString(&obRegistration.Altitude, L"300000");
	obRegistration.RegistrationContext = NULL;

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] ObRegisterCallbacks Test\n");

	return ObRegisterCallbacks(&obRegistration, &hRegistration);
}


VOID UnloadDriver(IN PDRIVER_OBJECT pDriver);

PFLT_FILTER Filter;

/*
 * This routine is called every time I/O is requested for:
 * - file creates (IRP_MJ_CREATE) such as ZwCreateFile and
 * - file metadata sets on files or file handles
 *   (IRP_MJ_SET_INFORMATION) such as ZwSetInformation.
 *
 * This is a pre-operation callback routine which means that the
 * IRP passes through this function on the way down the driver stack
 * to the respective device or driver to be handled.
 */
FLT_PREOP_CALLBACK_STATUS PreAntiDelete(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
	UNREFERENCED_PARAMETER(CompletionContext);

	/*
	 * This pre-operation callback code should be running at
	 * IRQL <= APC_LEVEL as stated in the docs:
	 * https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-preoperation-callback-routines
	 * and both ZwCreateFile and ZwSetInformaitonFile are also run at
	 * IRQL == PASSIVE_LEVEL:
	 * - ZwCreateFile: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-ntcreatefile#requirements
	 * - ZwSetInformationFile: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-ntsetinformationfile#requirements
	 */
	PAGED_CODE();

	/*
	 * By default, we don't want to call the post-operation routine
	 * because there's no need to further process it and also
	 * because there is none.
	 */
	FLT_PREOP_CALLBACK_STATUS ret = FLT_PREOP_SUCCESS_NO_CALLBACK;

	// We don't care about directories.
	BOOLEAN IsDirectory;
	NTSTATUS status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &IsDirectory);
	if (NT_SUCCESS(status)) {
		if (IsDirectory == TRUE) {
			return ret;
		}
	}
    
	/*
	 * We don't want anything that doesn't have the DELETE_ON_CLOSE
	 * flag.
	 */
	if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
		if (!FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
			return ret;
		}
	}

	/*
	 * We don't want anything that doesn't have either
	 * FileDispositionInformation or FileDispositionInformationEx or
	 * file renames (which can just simply rename the extension).
	 */
	if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
		switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
		case FileRenameInformation:
		case FileRenameInformationEx:
		case FileDispositionInformation:
		case FileDispositionInformationEx:
		case FileRenameInformationBypassAccessCheck:
		case FileRenameInformationExBypassAccessCheck:
		case FileShortNameInformation:
			break;
		default:
			return ret;
		}
	}

	/*
	 * Here we can check if we want to allow a specific process to fall
	 * through the checks, e.g. our own application.
	 * Since this is a PASSIVE_LEVEL operation, we can assume(?) that
	 * the thread context is the thread that requested the I/O. We can
	 * check the current thread and compare the EPROCESS of the
	 * authenticated application like so:
	 *
	 * if (IoThreadToProcess(Data->Thread) == UserProcess) {
	 *     return FLT_PREOP_SUCCESS_NO_CALLBACK;
	 * }
	 *
	 * Of course, we would need to find and save the EPROCESS of the
	 * application somewhere first. Something like a communication port
	 * could work.
	 */

	PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;
	// Make sure the file object exists.
	if (FltObjects->FileObject != NULL) {
		// Get the file name information with the normalized name.
		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
		if (NT_SUCCESS(status)) {
			// Now we want to parse the file name information to get the extension.
			FltParseFileNameInformation(FileNameInfo);			
			// Compare the file extension (case-insensitive) and check if it is protected.				
			char targets[8][40] = { UNINST, INF, CAT, SYS, URL, DB, MIRROR, GEO };
			//DbgPrintEx(DPFLTR_ACPI_ID, 0, "%wZ\n", &FileNameInfo->Name);
			size_t lengths[8] = { strlen(UNINST), strlen(INF), strlen(CAT), strlen(SYS), strlen(URL), strlen(DB), strlen(MIRROR), strlen(GEO)};
			for (int i = 0; i < 8; ++i) {				
				if (CompreFilenameWrapWithLength(FileNameInfo->Name, targets[i], lengths[i]))
				{										
					// Strings match, deny access!
					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					Data->IoStatus.Information = 0;
					// Complete the I/O request and send it back up.
					ret = FLT_PREOP_COMPLETE;
					break;
				}
			}
			// Clean up file name information.
			FltReleaseFileNameInformation(FileNameInfo);
		}
	}

	return ret;
}


CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE, 0, PreAntiDelete, NULL },				// DELETE_ON_CLOSE creation flag.
	{ IRP_MJ_SET_INFORMATION, 0, PreAntiDelete, NULL },		// FileInformationClass == FileDispositionInformation(Ex).
	{ IRP_MJ_OPERATION_END }
};

NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
	UNREFERENCED_PARAMETER(Flags);
	
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "Unload called.\n");

	// Unregister the minifilter.
	FltUnregisterFilter(Filter);

	return STATUS_SUCCESS;
}

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),				// Size
	FLT_REGISTRATION_VERSION,				// Version
	0,										// Flags
	NULL,									// ContextRegistration
	Callbacks,								// OperationRegistration
	Unload,									// FilterUnloadCallback
	NULL,									// InstanceSetupCallback
	NULL,									// InstanceQueryTeardownCallback
	NULL,									// InstanceTeardownStartCallback
	NULL,									// InstanceTeardownCompleteCallback
	NULL,									// GenerateFileNameCallback
	NULL,									// NormalizeNameComponentCallback
	NULL									// NormalizeContextCleanupCallback
};


NTSTATUS theAddDeviceFunction(
	PDRIVER_OBJECT DriverObject,
	PDEVICE_OBJECT PhysicalDeviceObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(PhysicalDeviceObject);
	return STATUS_NO_SUCH_DEVICE;
}

WCHAR g_TempString[512] = { 0, };
void NotifyRoutine(PEPROCESS Process, HANDLE ProcessId, \
	PPS_CREATE_NOTIFY_INFO CreateInfo)
{	
	if (CreateInfo == NULL)
	{		
		goto exit;
	}
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);
	memset(g_TempString, 0, sizeof(WCHAR) * 512);
	memcpy(g_TempString, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
	_wcsupr(g_TempString);	
	/*DbgPrintEx(DPFLTR_ACPI_ID, 0, "%ws\n", g_TempString);*/
	if (wcswcs(g_TempString, L"SC.EXE"))
	{
		memset(g_TempString, 0, sizeof(WCHAR) * 512);
		memcpy(g_TempString, CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine->Length);
		_wcsupr(g_TempString);
		//DbgPrintEx(DPFLTR_ACPI_ID, 0, "%ws\n", g_TempString);
		if (wcswcs(g_TempString, L"SC  DELETE PROCESSPROTECT") || wcswcs(g_TempString, L"SC  CONFIG PROCESSPROTECT"))
		{
			/*DbgPrintEx(DPFLTR_ACPI_ID, 0, "STATUS_UNSUCCESSFUL\n");*/
			CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
		}
	}
	else if (wcswcs(g_TempString, L"REGEDIT.EXE"))
	{		
		/*memset(g_TempString, 0, sizeof(WCHAR) * 512);
		memcpy(g_TempString, CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine->Length);
		_wcsupr(g_TempString);
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "%ws\n", g_TempString);*/
		//if (wcswcs(g_TempString, L"SC  DELETE PROCESSPROTECT") || wcswcs(g_TempString, L"SC  CONFIG PROCESSPROTECT"))
		//{
		//	DbgPrintEx(DPFLTR_ACPI_ID, 0, "STATUS_UNSUCCESSFUL\n");		
		//}
		CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
	}
exit:
	return;
}
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);			
	NTSTATUS ret = STATUS_SUCCESS;
		
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Load Driver\n");	
	pDriver->DriverUnload = UnloadDriver;	// 언로드 루틴 등록	
	PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, FALSE);
	pDriver->DriverExtension->AddDevice = theAddDeviceFunction;

	////InstallRegMonitor(pDriver);

	ret = ObRegExample();
	if (ret == STATUS_SUCCESS)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Success Registeration\n");
	}
	else
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Failed Registration %X\n", ret);
	}	

	NTSTATUS status = FltRegisterFilter(pDriver, &FilterRegistration, &Filter);
	if (!NT_SUCCESS(status)) 
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Failed to register file driver: %d\n", status);
		return STATUS_SUCCESS;
	}
	else
	{
		status = FltStartFiltering(Filter);
		if (!NT_SUCCESS(status)) {				
			DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Failed to start file driver.\n");
			// If we fail, we need to unregister the minifilter.
			FltUnregisterFilter(Filter);
		}
	}	

	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;

	 //Normalize name and symbolic link.
	RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, deviceSymLinkBuffer);

	// Create the device.
	ret = IoCreateDevice(pDriver,
		0, // For driver extension
		&deviceNameUnicodeString,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_UNKNOWN,
		FALSE,
		&g_MyDevice);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] IoCreateDevice ret: %d\n", ret);
	// Create the symbolic link
	ret = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] IoCreateSymbolicLink ret: %d\n", ret);
	pDriver->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CLOSE;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL;	
	return STATUS_SUCCESS;
}

/*
# Name  : UnloadDriver
# Param : PDRIVER_OBJECT
# Desc  : 드라이버 종료 루틴, 등록된 콜백 루틴을 해제
*/
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver)
{		
	UNREFERENCED_PARAMETER(pDriver);	
	UNICODE_STRING symLink;

	RtlInitUnicodeString(&symLink, deviceSymLinkBuffer);

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(pDriver->DeviceObject);
	if (hRegistration)
	{
		ObUnRegisterCallbacks(hRegistration);
	}			
	//UnInstallRegMonitor();
	PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, TRUE);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Unload Driver\n");		
}