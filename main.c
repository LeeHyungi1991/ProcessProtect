#include "common.h"

// ����� ���� DeviceType. �ڼ��� ������ https://learn.microsoft.com/ko-kr/windows-hardware/drivers/ddi/wdm/nf-wdm-iocompleterequest ����
#define SIOCTL_TYPE 40000
// �������� ����� IOCTL ��Ʈ�� �ڵ� ����. ������� ���α׷������� �����ϰ� ���� �Ǿ�� ��
// �Ķ���͵鿡 ���� �ڼ��� ������ https://learn.microsoft.com/ko-kr/windows-hardware/drivers/kernel/defining-i-o-control-codes ����
#define IOCTL_HELLO CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
// ����̹� �ε� ������ ���Ƶξ��� sc stop�� �ٽ� ����� �� ���������� ��ſ��� ���� ���Ҷ� ���� ������� ���α׷����� ��ӵ� base64��
#define AUTHENTICATION_CODE "KXyBI79u+65gTGNk2ZyamN/IOZBcTLN7dmJux5JekW4="

// ���� ��ȣ ������ �̸� ���� �ص�(���ڿ� ���� BSOD ������ �ϴ� defineó��)
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

VOID UnloadDriver(IN PDRIVER_OBJECT pDriver);

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


/*
* ���� ��� ���ø����̼ǰ��� ����� ���� �Լ�
* �Ʒ��� ������ ��������� �ҽ� �ڵ� ��ü
*/
/*
#include <Windows.h>
#include "WinIoCtl.h"
#include <stdio.h>
#include <Strsafe.h>

// Device Type
#define SIOCTL_TYPE 40000

#define AUTHENTICATION_CODE "KXyBI79u+65gTGNk2ZyamN/IOZBcTLN7dmJux5JekW4="

//Ŀ�θ��� ����� IOCTL ��Ʈ�� �ڵ� ����. Ŀ�θ�� ���α׷������� �����ϰ� ���� �Ǿ�� ��
//1��° �Ķ����: Device Type : I/O Control �ڵ尡 ���Ǵ� ����̽� ��ġ ����
//2��° �Ķ����: Function : ��ü���� ���� �ڵ带 �з� (0~4095 [0~2047 : ����ũ�μ���Ʈ���� ����]/[2047(0x800)~4095(0xFFF) : ��밡��])
//3��° �Ķ����: Method : ���� ���ø����̼ǰ� ����̽��� ����� �� �� ���۸� ��� �� ���ΰ��� ����
//4��° �Ķ����: Access : �ش��ϴ� I/O Control Code�� ���� ���Ǵ� ������ �뵵�� ����
#define IOCTL_HELLO CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
int __cdecl main(int argc, char* argv[])
{
	const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\MyDevice";
	HANDLE hDevice;	
	char* code = AUTHENTICATION_CODE; // �����ڵ� ����ȭ
	DWORD dwBytesRead = 0; // Ŀ�ηκ��� �޴� �޼����� ��Ʈ���� üũ�ϱ� ���� 4����Ʈ DWORD ����
	char ReadBuffer[50] = { 0 }; // Ŀ�ηκ��� �޴� �޼����� ��� ���� ����
	
	// Ŀ�ΰ� ����� �� ���̴� I/O ����̽��� �ɺ��� ��ũ�� ��ȸ�Ͽ� �����ϰ� �ش� ����̽��� �ڵ��� ����
	// 5��° �Ķ����Ϳ� OPEN_EXISTING�� �Ѱܼ� �ش� I/O ����̽��� �����Ҷ���
	// �������� �ڵ��� �����ϰ� �ȴ�.
	// ���� ��� ����� �Ǵ� ����̹��� �ε��� �� "\\DosDevices\\MyDevice"�� �ش��ϴ� �ɺ��� ��ũ�� �����ϰ� �ȴ�.
	
	hDevice = CreateFile(deviceSymLinkBuffer, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	printf("Handle : %p\n", hDevice);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	// Ŀ�ο� �����ڵ� ���ڿ��� �۽��԰� ���ÿ� ReadBuffer�� Ŀ�ηκ��� ���ŵ� ���ڿ��� ��´�.
	DeviceIoControl(hDevice, IOCTL_HELLO, code, strlen(code), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
	printf("Message received from kerneland : %s\n", ReadBuffer);
	printf("Bytes read : %d\n", dwBytesRead);

	CloseHandle(hDevice); // ���� �ʿ������ �ڵ��� �ݴ´�.
	return 0;
}
*/
NTSTATUS Function_IRP_DEVICE_CONTROL(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{	
	UNREFERENCED_PARAMETER(Irp);
	PIO_STACK_LOCATION pIoStackLocation;
	PCHAR welcome = "Hello from kerneland.";

	// IRP�� �ý��� ���ۿ� �����Ͽ� ������忡�� ���� �޼����� ����
	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
	char* pChar;
	pChar = pBuf;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_HELLO:
		{
			DbgPrintEx(DPFLTR_ACPI_ID, 0, "IOCTL HELLO.\n");
			if (strcmp(pChar, AUTHENTICATION_CODE) == 0)
			{
				/*
				����̽� ������Ʈ�� ����̽� ���ÿ� �����Ҷ� ȣ��Ǵ� �Լ��� ���������ν�
				����̽��� �ν��� �� �ֵ��� �Ͽ� sc stop���� ���񽺸� ������ �� �ִ� ���°� �ȴ�.
				*/
				pDeviceObject->DriverObject->DriverExtension->AddDevice = NULL;
				DbgPrintEx(DPFLTR_ACPI_ID, 0, "AUTHENTICATED!!\n");
			}
			// ���ڿ��� �����ϱ� ��, IRP�� �ý��� ���۸� ����.
			RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
			// IRP�� �ý��� ���� �����Ϳ� ���ڿ��� �����ϴ� ������� ������� ���ø����̼ǿ� �۽��ϴ� �κ�
			RtlCopyMemory(pBuf, welcome, strlen(welcome));
			break;
		}		
	}

	// ���������� IO����� �������Ѵ�.	
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = strlen(welcome);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// ��ε� ��, ObRegisterCallbacks�� ����� ��ϵǾ����� �Ǻ��� ����ϱ� ���� ���������� ����
PVOID hRegistration = NULL;
/*
# Name  : ObRegisterCallbackStart
# Param : None
# Desc  : OB_CALLBACK, OPERATION_REGISTRATION ����ü �ʱ�ȭ �� ObRegisterCallbacks �� �̿��� �ݹ� ��ƾ ���
*/
NTSTATUS ObRegisterCallbackStart()
{
	OB_CALLBACK_REGISTRATION obRegistration = { 0, };
	OB_OPERATION_REGISTRATION opRegistration = { 0, };

	opRegistration.ObjectType = PsProcessType;
	opRegistration.PreOperation = PreCallback;	// PreOperation ���, ���� ���� ��ġ�� callbacks.h
	opRegistration.PostOperation = PostCallback;	// PostOperation ���,  ���� ���� ��ġ�� callbacks.h
	opRegistration.Operations = OB_OPERATION_HANDLE_CREATE;	// Create �Ǵ� Open �� ����

	obRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	obRegistration.OperationRegistrationCount = 1;
	obRegistration.OperationRegistration = &opRegistration;
	RtlInitUnicodeString(&obRegistration.Altitude, L"300000");
	obRegistration.RegistrationContext = NULL;

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] ObRegisterCallbacks Test\n");

	return ObRegisterCallbacks(&obRegistration, &hRegistration);
}

PFLT_FILTER Filter;
/* ���� ����/�̸��������κ��� ��ȣ�Ҷ� ������ ���͸��ϴ� ������ ��� �Լ�
 * �ؿ� ��α׿� ������(https://0x00sec.org/t/kernel-mode-rootkits-file-deletion-protection/7616)�� ������ ��������
 * �ҽ��� �����ͼ� ���� �� �뵵�� �°Բ� �����Ͽ� ����Ͽ���.
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

/*
# Name  : NotifyRoutine
# Param : 
	PEPROCESS Process: ���μ��� ����ü
	HANDLE ProcessId: ���μ��� �ڵ� 
	PPS_CREATE_NOTIFY_INFO CreateInfo: ���μ��� ������ ������ ���� ����ü
# Desc  : OB_CALLBACK, OPERATION_REGISTRATION ����ü �ʱ�ȭ �� ObRegisterCallbacks �� �̿��� �ݹ� ��ƾ ���
*/
void NotifyRoutine(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{	
	if (CreateInfo == NULL)
	{		
		goto exit;
	}
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);
	// g_TempString�� �˳��ϰ� sizeof(WCHAR) * 512�� �޸� �Ҵ�
	memset(g_TempString, 0, sizeof(WCHAR) * 512);
	// g_TempString�� ���μ��� ���� �̹������ϸ� ���ڿ��� ����
	memcpy(g_TempString, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
	_wcsupr(g_TempString); // �빮�� ��ȯ
	//DbgPrintEx(DPFLTR_ACPI_ID, 0, "%ws\n", g_TempString);
	if (wcswcs(g_TempString, L"SC.EXE")) // SC.EXE�� �̹������ϸ��� �κй��ڿ��� ���
	{		
		// g_TempString�� �޸� ���Ҵ�
		memset(g_TempString, 0, sizeof(WCHAR) * 512);
		// g_TempString�� ���μ��� ������ ���� �Էµ� Ŀ�ǵ���� ������ ���ڿ��� ����
		memcpy(g_TempString, CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine->Length);
		_wcsupr(g_TempString);
		//DbgPrintEx(DPFLTR_ACPI_ID, 0, "%ws\n", g_TempString);		
		if (wcswcs(g_TempString, L"SC  DELETE PROCESSPROTECT") || wcswcs(g_TempString, L"SC  CONFIG PROCESSPROTECT"))
		{	
			// ���μ��� ���� ���¸� STATUS_UNSUCCESSFUL�� �����Ͽ� ���������� ���μ����� ������� �ʵ��� �Ѵ�.
			CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
		}
	}
	else if (wcswcs(g_TempString, L"REGEDIT.EXE"))
	{		
		CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL; // ������Ʈ�� ������ ������ ���´�
	}
exit:
	return;
}

/*
# Name  : DriverEntry
# Param :
	PDRIVER_OBJECT pDriver: ����̹� ������Ʈ
	PUNICODE_STRING pRegPath: ����̹��� ������Ʈ�� Ű ���
# Desc  : ����̹��� ���񽺸� �����ϸ� ����Ǵ� �����Լ�
*/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);			
	NTSTATUS status = STATUS_SUCCESS;
		
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Load Driver\n");	
	pDriver->DriverUnload = UnloadDriver;	// ��ε� ��ƾ ���	

	/* NotifyRoutine�� �����ϴ� �Ϳ� �ΰ��� ������ �ִ�.
	1. sc delete -> ��ǻ�� ����� -> ���μ��� �ڵ����� �ȵ��� �ذ��ϱ� ����,
	sc delete ��ɾ� ���� ��ü�� ���� ����, ���ϸ��� SC.EXE�̸� CommandLine Buffer�� 'SC  DELETE PROCESSPROTECT' Ȥ�� 'SC  CONFIG PROCESSPROTECT'�� ���� ��쿡
	���μ����� ������ ���� ��ƾ �Լ��� ���� 

	2. ������Ʈ�� ������� sys������ ���� Ȥ�� �����ϴ� ���� ���� ���ؼ� ���μ����� ������ ��,
	ImageFileName(���ϸ�)�� REGEDIT.EXE�̸� ���μ��� ������ ���´�.
	*/
	PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, FALSE); 
	/* 
	����̽� ������Ʈ�� ����̽� ���ÿ� �����Ͽ� ȣ�� �ɶ� STATUS_NO_SUCH_DEVICE�� �����ϵ��� �ϴ� �Լ��� �����Ͽ�,
	sc�� net ���μ����� �ش� ����̽��� �ν��� �� ���� ����,
	sc stop �̳� net stop���� ���񽺸� ������ �� ������ ���´�.
	*/
	pDriver->DriverExtension->AddDevice = theAddDeviceFunction; // STATUS_NO_SUCH_DEVICE�� �����ϴ� ��(Empty)�Լ� ���

	/* ���μ��� ���� ���� */
	status = ObRegisterCallbackStart(); // ObRegisterCallback ����� �����Ѵ�.
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Failed Registration %X\n", status);		
	}	
	
	/* ��ȣ�Ϸ��� ���α׷� ������ �̸�����/���� ������ ���� ���� �ý��� ���͸� ���� */
	status = FltRegisterFilter(pDriver, &FilterRegistration, &Filter); // ���� �ý��� ���� ����̹� ���. FilterRegistration ����ü ���� ���͸� ������ ���Ե� �Լ� �� Unload�� ȣ��Ǵ� �Լ��� ���ǵǾ� ����
	if (NT_SUCCESS(status))
	{		
		status = FltStartFiltering(Filter); // ���� �ý��� ���� ����̹� ��Ͽ� �����ϸ� �ش� ����̹��� �۵���Ų��.
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Failed to start file driver.\n");			
			FltUnregisterFilter(Filter); // ���� �ý��� ���� ����̹� ���ۿ� �����ϸ� ����� �����Ѵ�.
		}		
	}
	else
	{	
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Failed to register file driver: %d\n", status);		
	}	

	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;

	 //Normalize name and symbolic link.
	RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, deviceSymLinkBuffer);

	// ������忡�� ����� I/O ����̽��� ������� ���α׷��� ���� ����̹� �ε� ������ Ŀ�ο��� �̸� �������ش�.
	// ������� ���α׷������� CreateFile(deviceSymLinkBuffer, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL) �Լ��� ȣ���Ͽ�
	// I/O ����̽��� �̹� ������ ��쿡�� �ڵ��� ���� �� �ְ� �ȴ�.
	status = IoCreateDevice(pDriver,
		0, // For driver extension
		&deviceNameUnicodeString,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_UNKNOWN,
		FALSE,
		&g_MyDevice);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] IoCreateDevice ret: %d\n", status);	

	if (NT_SUCCESS(status)) // ���������� I/O ����̽��� �����ߴٸ�
	{
		//������忡�� ������ �̿��� g_MyDevice�� �ɺ��� ��ũ ����
		status = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] IoCreateSymbolicLink ret: %d\n", status);
		pDriver->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE; // IRP ��û ������ �ݹ� �Լ�
		pDriver->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CLOSE; // IRP ��û ����� �ݹ� �Լ�
		pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL; // IRP �ۼ��ſ� ����� ���� �ݹ� �Լ� (���� �ҽ������� �� �κ��� �������� ����ϴµ� ���ȴ�.)			
	}			
	return STATUS_SUCCESS;
}

/*
# Name  : UnloadDriver
# PDRIVER_OBJECT pDriver: ����̹� ������Ʈ
# Desc  : ����̹� ���� ��ƾ, ��ϵ� �ݹ� ��ƾ�� ����
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
	PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, TRUE);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Unload Driver\n");		
}