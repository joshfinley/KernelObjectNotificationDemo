#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <wdf.h>
#include <wdm.h>

typedef struct _CALLBACK_ENTRY
{
	UINT16 Version; // 0x0
	UINT16 OperationRegistrationCount; // 0x2
	UINT32 unk1; // 0x4
	PVOID RegistrationContext; // 0x8
	UNICODE_STRING Altitude; // 0x10
} CALLBACK_ENTRY, * PCALLBACK_ENTRY;

typedef struct _OBJECT_CALLBACK_ENTRY
{
	LIST_ENTRY CallbackList;
	OB_OPERATION Operations;
	ULONG Active;
	/*OB_HANDLE*/ PCALLBACK_ENTRY CallbackEntry;
	POBJECT_TYPE ObjectType;
	POB_PRE_OPERATION_CALLBACK  PreOperation;
	POB_POST_OPERATION_CALLBACK PostOperation;
} OBJECT_CALLBACK_ENTRY, * POBJECT_CALLBACK_ENTRY;

typedef struct _OBP_LOOKUP_CONTEXT {
	PVOID DirectoryObject;
	BOOLEAN Locked;
	UCHAR LockStateSignature;
} OBP_LOOKUP_CONTEXT, * POBP_LOOKUP_CONTEXT;

typedef struct _OBJECT_DIRECTORY {
	PVOID HashBuckets[37];
	PVOID Lock;
	ULONG Reserved1[2];
	PVOID DeviceMap;
	ULONG Reserved2[1];
	ULONG SessionId;
} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG CoverageSectionSize;
	PVOID CoverageSection;
	PVOID LoadedImports;
	PVOID Spare;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

PVOID g_pObCallbackRegHandle;


VOID Unload(_In_ PDRIVER_OBJECT DriverObject);

NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

OB_PREOP_CALLBACK_STATUS ObjectNotificationCallback(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION Info
);


#define PROCESS_TERMINATE                 (0x0001)  
#define PROCESS_CREATE_THREAD             (0x0002)  
#define PROCESS_SET_SESSIONID             (0x0004)  
#define PROCESS_VM_OPERATION              (0x0008)  
#define PROCESS_VM_READ                   (0x0010)  
#define PROCESS_VM_WRITE                  (0x0020)  
#define PROCESS_DUP_HANDLE                (0x0040)  
#define PROCESS_CREATE_PROCESS            (0x0080)  
#define PROCESS_SET_QUOTA                 (0x0100)  
#define PROCESS_SET_INFORMATION           (0x0200)  
#define PROCESS_QUERY_INFORMATION         (0x0400)  
#define PROCESS_SUSPEND_RESUME            (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION   (0x2000)


OB_PREOP_CALLBACK_STATUS ObjectNotificationCallback(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION Info)
{
	UNREFERENCED_PARAMETER(RegistrationContext); // Unreferenced parameter

	// Initialize local variables
	NTSTATUS Status;
	BOOL AttemptRead = FALSE;
	BOOL AttemptQuery = FALSE;
	HANDLE ProcessId = NULL;
	PUNICODE_STRING ProcessImageName = NULL;
	UNICODE_STRING TargetProcessImageName = RTL_CONSTANT_STRING(L"lsass.exe");

	// Pointer checks
	if (Info == NULL || Info->ObjectType == NULL || Info->Object == NULL) {
		return OB_PREOP_SUCCESS;
	}

	// Filter only for process objects
	if (Info->ObjectType != *PsProcessType) {
		return OB_PREOP_SUCCESS;
	}

	// Get target process ID
	ProcessId = PsGetProcessId((PEPROCESS)Info->Object);
	if (ProcessId == NULL) {
		return OB_PREOP_SUCCESS;
	}
	KdPrint(("Target Process ID: %p\n", ProcessId));

	// Get target process image name
	Status = SeLocateProcessImageName((PEPROCESS)Info->Object, &ProcessImageName);
	if (!NT_SUCCESS(Status) || ProcessImageName == NULL) {
		return OB_PREOP_SUCCESS; // Return for demo purposes
	}

	// Compare target image name with lsass.exe
	if (RtlCompareUnicodeString(&TargetProcessImageName, ProcessImageName, TRUE) != 0) {
		ExFreePool(ProcessImageName); // Don't forget to free the allocated memory
		return OB_PREOP_SUCCESS;
	}
	ExFreePool(ProcessImageName); // Don't forget to free the allocated memory
	KdPrint(("Lsass process access attempt\n"));

	// Log operation information
	KdPrint(("Operation: %d\n", Info->Operation));
	KdPrint(("Call context: 0x%08X\n", Info->CallContext));
	KdPrint(("Kernel handle: 0x%08X\n", Info->KernelHandle));

	// Handle specific operations
	if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
		KdPrint(("Operation: OB_OPERATION_HANDLE_CREATE\n"));
		if (Info->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_VM_READ) {
			KdPrint(("Access request type: PROCESS_VM_READ\n"));
		}
		else if (Info->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_QUERY_INFORMATION) {
			KdPrint(("Access request type: PROCESS_QUERY_INFORMATION\n"));
		}
	}
	else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
		KdPrint(("Operation: OB_OPERATION_HANDLE_DUPLICATE\n"));

		// Check desired access types
		if (Info->Parameters->DuplicateHandleInformation.DesiredAccess & PROCESS_VM_READ) {
			KdPrint(("Access request type includes PROCESS_VM_READ\n"));
			AttemptRead = TRUE;
		}
		if (Info->Parameters->DuplicateHandleInformation.DesiredAccess & PROCESS_QUERY_INFORMATION) {
			KdPrint(("Access request type includes PROCESS_QUERY_INFORMATION\n"));
			AttemptQuery = TRUE;
		}
	}

	// Check calling process
	PEPROCESS CurrentProcess = IoGetCurrentProcess();
	HANDLE CurrentProcessId = PsGetProcessId(CurrentProcess);
	PUNICODE_STRING CurrentProcessImageName = NULL;
	KdPrint(("Current Process ID: %p\n", CurrentProcessId));

	if (NT_SUCCESS(SeLocateProcessImageName(CurrentProcess, &CurrentProcessImageName)) && CurrentProcessImageName) {
		KdPrint(("User-mode Process ID trying to get the handle: %p\n", CurrentProcessId));
		KdPrint(("User-mode Process Image Name trying to get the handle: %wZ\n", CurrentProcessImageName));
		ExFreePool(CurrentProcessImageName);
	}

	// Block or modify access if necessary
	if (AttemptRead || AttemptQuery) {
		if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
			Info->Parameters->CreateHandleInformation.DesiredAccess = 0; // Set access rights to none
		}
		else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
			Info->Parameters->DuplicateHandleInformation.DesiredAccess = 0; // Set access rights to none
		}
	}

	return OB_PREOP_SUCCESS;
}

extern POBJECT_TYPE* IoDriverObjectType;

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	// Initialize variables
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS Status = STATUS_SUCCESS;
	OB_CALLBACK_REGISTRATION CallbackReg;
	OB_OPERATION_REGISTRATION OperationReg;
	OBJECT_CALLBACK_ENTRY CurrentOperationEntry;

	RtlZeroMemory(&CallbackReg, sizeof(OB_CALLBACK_REGISTRATION));
	RtlZeroMemory(&OperationReg, sizeof(OB_OPERATION_REGISTRATION));
	RtlZeroMemory(&CurrentOperationEntry, sizeof(OBJECT_CALLBACK_ENTRY));

	// Set MJ Dispatchers
	DriverObject->DriverUnload = Unload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;

	// Initialize Device OBJ
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KernelObjectNotificationDemo");

	PDEVICE_OBJECT DeviceObject;
	Status = IoCreateDevice(
		DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DeviceObject
	);

	if (!NT_SUCCESS(Status)) {
		KdPrint(("Failed to create device object (0x%08X)\n", Status));

		// if a device object was actually created
		if (DeviceObject != NULL) {
			IoDeleteDevice(DeviceObject);
		}

		return Status;
	}

	// Initialize symbolic link
	UNICODE_STRING SymLink = RTL_CONSTANT_STRING(L"\\??\\KernelObjectNotificationDemo");
	Status = IoCreateSymbolicLink(&SymLink, &DeviceName);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("Failed to create symbolic link (0X%08X)\n", Status));
		IoDeleteDevice(DeviceObject);
		return Status;
	}

	//
	// Demonstration of registering a callback
	//
	CallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
	CallbackReg.OperationRegistrationCount = 1;
	RtlInitUnicodeString(&CallbackReg.Altitude, L"28121.011204");
	CallbackReg.RegistrationContext = NULL;

	OperationReg.ObjectType = PsProcessType;
	OperationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	OperationReg.PreOperation = ObjectNotificationCallback;

	CallbackReg.OperationRegistration = &OperationReg;

	Status = ObRegisterCallbacks(&CallbackReg, &g_pObCallbackRegHandle);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("Failed to register object notification callback (0X%08X)\n", Status));
		IoDeleteDevice(DeviceObject);
		return Status;
	}

	return STATUS_SUCCESS;
}

VOID Unload(_In_ PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\KernelObjectNotificationDemo");
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);

	// Delete callback
	ObUnRegisterCallbacks(g_pObCallbackRegHandle);

	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

PVOID GetKernelProcAddress(LPCWSTR szFunctionName) {
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, szFunctionName);

	return MmGetSystemRoutineAddress(&funcName);
}

