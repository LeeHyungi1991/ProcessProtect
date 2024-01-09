#include "common.h"

// 사용자 정의 DeviceType. 자세한 내용은 https://learn.microsoft.com/ko-kr/windows-hardware/drivers/ddi/wdm/nf-wdm-iocompleterequest 참조
#define SIOCTL_TYPE 40000
// 유저모드와 통신할 IOCTL 컨트롤 코드 설정. 유저모드 프로그램에서도 동일하게 설정 되어야 함
// 파라미터들에 대한 자세한 내용은 https://learn.microsoft.com/ko-kr/windows-hardware/drivers/kernel/defining-i-o-control-codes 참조
#define IOCTL_HELLO CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
// 드라이버 로드 시점에 막아두었던 sc stop을 다시 허용할 때 유저모드와의 통신에서 값을 비교할때 쓰는 유저모드 프로그램과의 약속된 base64값
#define AUTHENTICATION_CODE "KXyBI79u+65gTGNk2ZyamN/IOZBcTLN7dmJux5JekW4="

// 파일 보호 대상들을 미리 정의 해둠(문자열 관련 BSOD 때문에 일단 define처리)
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
* 유저 모드 어플리케이션과의 통신을 위한 함수
* 아래의 내용은 유저모드쪽 소스 코드 전체
*/
/*
#include <Windows.h>
#include "WinIoCtl.h"
#include <stdio.h>
#include <Strsafe.h>

// Device Type
#define SIOCTL_TYPE 40000

#define AUTHENTICATION_CODE "KXyBI79u+65gTGNk2ZyamN/IOZBcTLN7dmJux5JekW4="

//커널모드와 통신할 IOCTL 컨트롤 코드 설정. 커널모드 프로그램에서도 동일하게 설정 되어야 함
//1번째 파라미터: Device Type : I/O Control 코드가 사용되는 디바이스 장치 유형
//2번째 파라미터: Function : 구체적인 수행 코드를 분류 (0~4095 [0~2047 : 마이크로소프트에서 예약]/[2047(0x800)~4095(0xFFF) : 사용가능])
//3번째 파라미터: Method : 유저 어플리케이션과 디바이스간 통신을 할 때 버퍼를 어떻게 할 것인가를 정의
//4번째 파라미터: Access : 해당하는 I/O Control Code와 같이 사용되는 버퍼의 용도를 정의
#define IOCTL_HELLO CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
int __cdecl main(int argc, char* argv[])
{
	const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\MyDevice";
	HANDLE hDevice;	
	char* code = AUTHENTICATION_CODE; // 인증코드 정규화
	DWORD dwBytesRead = 0; // 커널로부터 받는 메세지의 비트수를 체크하기 위한 4바이트 DWORD 변수
	char ReadBuffer[50] = { 0 }; // 커널로부터 받는 메세지를 담기 위한 버퍼
	
	// 커널과 통신할 때 쓰이는 I/O 디바이스를 심볼릭 링크로 조회하여 오픈하고 해당 디바이스의 핸들을 리턴
	// 5번째 파라이터에 OPEN_EXISTING를 넘겨서 해당 I/O 디바이스가 존재할때만
	// 정상적인 핸들을 리턴하게 된다.
	// 현재 통신 대상이 되는 드라이버는 로드할 때 "\\DosDevices\\MyDevice"에 해당하는 심볼릭 링크를 생성하게 된다.
	
	hDevice = CreateFile(deviceSymLinkBuffer, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	printf("Handle : %p\n", hDevice);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	// 커널에 인증코드 문자열을 송신함과 동시에 ReadBuffer에 커널로부터 수신된 문자열을 담는다.
	DeviceIoControl(hDevice, IOCTL_HELLO, code, strlen(code), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
	printf("Message received from kerneland : %s\n", ReadBuffer);
	printf("Bytes read : %d\n", dwBytesRead);

	CloseHandle(hDevice); // 이제 필요없어진 핸들은 닫는다.
	return 0;
}
*/
NTSTATUS Function_IRP_DEVICE_CONTROL(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{	
	UNREFERENCED_PARAMETER(Irp);
	PIO_STACK_LOCATION pIoStackLocation;
	PCHAR welcome = "Hello from kerneland.";

	// IRP의 시스템 버퍼에 접근하여 유저모드에서 보낸 메세지를 수신
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
				디바이스 오브젝트가 디바이스 스택에 동참할때 호출되는 함수를 제거함으로써
				디바이스를 인식할 수 있도록 하여 sc stop으로 서비스를 종료할 수 있는 상태가 된다.
				*/
				pDeviceObject->DriverObject->DriverExtension->AddDevice = NULL;
				DbgPrintEx(DPFLTR_ACPI_ID, 0, "AUTHENTICATED!!\n");
			}
			// 문자열을 복사하기 전, IRP의 시스템 버퍼를 비운다.
			RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
			// IRP의 시스템 버퍼 포인터에 문자열을 복사하는 방식으로 유저모드 어플리케이션에 송신하는 부분
			RtlCopyMemory(pBuf, welcome, strlen(welcome));
			break;
		}		
	}

	// 유저모드와의 IO통신을 마무리한다.	
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = strlen(welcome);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// 언로드 시, ObRegisterCallbacks가 제대로 등록되었는지 판별에 사용하기 위해 전역변수로 선언
PVOID hRegistration = NULL;
/*
# Name  : ObRegisterCallbackStart
# Param : None
# Desc  : OB_CALLBACK, OPERATION_REGISTRATION 구조체 초기화 및 ObRegisterCallbacks 를 이용해 콜백 루틴 등록
*/
NTSTATUS ObRegisterCallbackStart()
{
	OB_CALLBACK_REGISTRATION obRegistration = { 0, };
	OB_OPERATION_REGISTRATION opRegistration = { 0, };

	opRegistration.ObjectType = PsProcessType;
	opRegistration.PreOperation = PreCallback;	// PreOperation 등록, 로직 구현 위치는 callbacks.h
	opRegistration.PostOperation = PostCallback;	// PostOperation 등록,  로직 구현 위치는 callbacks.h
	opRegistration.Operations = OB_OPERATION_HANDLE_CREATE;	// Create 또는 Open 시 동작

	obRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	obRegistration.OperationRegistrationCount = 1;
	obRegistration.OperationRegistration = &opRegistration;
	RtlInitUnicodeString(&obRegistration.Altitude, L"300000");
	obRegistration.RegistrationContext = NULL;

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] ObRegisterCallbacks Test\n");

	return ObRegisterCallbacks(&obRegistration, &hRegistration);
}

PFLT_FILTER Filter;
/* 파일 삭제/이름변경으로부터 보호할때 파일을 필터링하는 로직이 담긴 함수
 * 해외 블로그에 포스팅(https://0x00sec.org/t/kernel-mode-rootkits-file-deletion-protection/7616)된 내용을 바탕으로
 * 소스를 가져와서 내가 쓸 용도에 맞게끔 변경하여 사용하였다.
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
	PEPROCESS Process: 프로세스 구조체
	HANDLE ProcessId: 프로세스 핸들 
	PPS_CREATE_NOTIFY_INFO CreateInfo: 프로세스 생성시 정보를 담은 구조체
# Desc  : OB_CALLBACK, OPERATION_REGISTRATION 구조체 초기화 및 ObRegisterCallbacks 를 이용해 콜백 루틴 등록
*/
void NotifyRoutine(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{	
	if (CreateInfo == NULL)
	{		
		goto exit;
	}
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);
	// g_TempString을 넉넉하게 sizeof(WCHAR) * 512로 메모리 할당
	memset(g_TempString, 0, sizeof(WCHAR) * 512);
	// g_TempString에 프로세스 실행 이미지파일명 문자열을 복사
	memcpy(g_TempString, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
	_wcsupr(g_TempString); // 대문자 변환
	//DbgPrintEx(DPFLTR_ACPI_ID, 0, "%ws\n", g_TempString);
	if (wcswcs(g_TempString, L"SC.EXE")) // SC.EXE이 이미지파일명의 부분문자열일 경우
	{		
		// g_TempString에 메모리 재할당
		memset(g_TempString, 0, sizeof(WCHAR) * 512);
		// g_TempString에 프로세스 실행을 위해 입력된 커맨드라인 버퍼의 문자열을 복사
		memcpy(g_TempString, CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine->Length);
		_wcsupr(g_TempString);
		//DbgPrintEx(DPFLTR_ACPI_ID, 0, "%ws\n", g_TempString);		
		if (wcswcs(g_TempString, L"SC  DELETE PROCESSPROTECT") || wcswcs(g_TempString, L"SC  CONFIG PROCESSPROTECT"))
		{	
			// 프로세스 생성 상태를 STATUS_UNSUCCESSFUL로 전달하여 최종적으로 프로세스가 실행되지 않도록 한다.
			CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
		}
	}
	else if (wcswcs(g_TempString, L"REGEDIT.EXE"))
	{		
		CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL; // 레지스트리 편집기 실행을 막는다
	}
exit:
	return;
}

/*
# Name  : DriverEntry
# Param :
	PDRIVER_OBJECT pDriver: 드라이버 오브젝트
	PUNICODE_STRING pRegPath: 드라이버의 레지스트리 키 경로
# Desc  : 드라이버로 서비스를 시작하면 실행되는 메인함수
*/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);			
	NTSTATUS status = STATUS_SUCCESS;
		
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Load Driver\n");	
	pDriver->DriverUnload = UnloadDriver;	// 언로드 루틴 등록	

	/* NotifyRoutine을 구현하는 것엔 두가지 목적이 있다.
	1. sc delete -> 컴퓨터 재시작 -> 프로세스 자동시작 안됨을 해결하기 위해,
	sc delete 명령어 실행 자체를 막기 위해, 파일명이 SC.EXE이며 CommandLine Buffer에 'SC  DELETE PROCESSPROTECT' 혹은 'SC  CONFIG PROCESSPROTECT'이 있을 경우에
	프로세스를 실행을 막는 루틴 함수를 정의 

	2. 레지스트리 편집기로 sys파일을 변조 혹은 삭제하는 것을 막기 위해서 프로세스를 시작할 때,
	ImageFileName(파일명)이 REGEDIT.EXE이면 프로세스 실행을 막는다.
	*/
	PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, FALSE); 
	/* 
	디바이스 오브젝트가 디바이스 스택에 동참하여 호출 될때 STATUS_NO_SUCH_DEVICE를 리턴하도록 하는 함수를 정의하여,
	sc나 net 프로세스가 해당 디바이스를 인식할 수 없게 만들어서,
	sc stop 이나 net stop으로 서비스를 중지할 수 없도록 막는다.
	*/
	pDriver->DriverExtension->AddDevice = theAddDeviceFunction; // STATUS_NO_SUCH_DEVICE를 리턴하는 빈(Empty)함수 등록

	/* 프로세스 종료 방지 */
	status = ObRegisterCallbackStart(); // ObRegisterCallback 등록을 시작한다.
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Failed Registration %X\n", status);		
	}	
	
	/* 보호하려는 프로그램 파일의 이름변경/삭제 방지를 위한 파일 시스템 필터링 로직 */
	status = FltRegisterFilter(pDriver, &FilterRegistration, &Filter); // 파일 시스템 필터 드라이버 등록. FilterRegistration 구조체 내에 필터링 로직이 포함된 함수 및 Unload시 호출되는 함수가 정의되어 있음
	if (NT_SUCCESS(status))
	{		
		status = FltStartFiltering(Filter); // 파일 시스템 필터 드라이버 등록에 성공하면 해당 드라이버를 작동시킨다.
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Failed to start file driver.\n");			
			FltUnregisterFilter(Filter); // 파일 시스템 필터 드라이버 시작에 실패하면 등록을 해제한다.
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

	// 유저모드에서 사용할 I/O 디바이스를 유저모드 프로그램을 위해 드라이버 로드 시점에 커널에서 미리 생성해준다.
	// 유저모드 프로그램에서는 CreateFile(deviceSymLinkBuffer, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL) 함수를 호출하여
	// I/O 디바이스가 이미 존재할 경우에만 핸들을 얻을 수 있게 된다.
	status = IoCreateDevice(pDriver,
		0, // For driver extension
		&deviceNameUnicodeString,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_UNKNOWN,
		FALSE,
		&g_MyDevice);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] IoCreateDevice ret: %d\n", status);	

	if (NT_SUCCESS(status)) // 성공적으로 I/O 디바이스를 생성했다면
	{
		//유저모드에서 참조에 이용할 g_MyDevice의 심볼릭 링크 생성
		status = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] IoCreateSymbolicLink ret: %d\n", status);
		pDriver->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE; // IRP 요청 생성시 콜백 함수
		pDriver->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CLOSE; // IRP 요청 종료시 콜백 함수
		pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL; // IRP 송수신용 사용자 정의 콜백 함수 (현재 소스에서는 이 부분이 유저모드와 통신하는데 사용된다.)			
	}			
	return STATUS_SUCCESS;
}

/*
# Name  : UnloadDriver
# PDRIVER_OBJECT pDriver: 드라이버 오브젝트
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
	PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, TRUE);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Unload Driver\n");		
}