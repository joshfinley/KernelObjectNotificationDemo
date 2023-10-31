#include <ntifs.h>
#include <ntddk.h>

PVOID g_pObCallbackRegHandle;

VOID Unload(_In_ PDRIVER_OBJECT DriverObject);

NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

OB_PREOP_CALLBACK_STATUS ObjectNotificationCallback(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION Info
);

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS Status = STATUS_SUCCESS;
	OB_CALLBACK_REGISTRATION CallbackReg;
	OB_OPERATION_REGISTRATION OperationReg;

	RtlZeroMemory(&CallbackReg, sizeof(OB_CALLBACK_REGISTRATION));
	RtlZeroMemory(&OperationReg, sizeof(OB_OPERATION_REGISTRATION));

	DriverObject->DriverUnload = Unload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NULL;

	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\ObjectNotifDemo");

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(
		DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DeviceObject
	);

	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create device object (0x%08X)\n", status));

		// if a device object was actually created
		if (DeviceObject != NULL) {
			IoDeleteDevice(DeviceObject);
		}

		return status;
	}

	UNICODE_STRING SymLink = RTL_CONSTANT_STRING(L"\\??\\");
	status = IoCreateSymbolicLink(&SymLink, &DeviceName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create symbolic link (0x&08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	CallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
	CallbackReg.OperationRegistrationCount = 1;
	RtlInitUnicodeString(&CallbackReg.Altitude, L"28121.011204");
	CallbackReg.RegistrationContext = NULL;

	OperationReg.ObjectType = PsProcessType;
	OperationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	OperationReg.PreOperation = ObjectNotificationCallback;

	CallbackReg.OperationRegistration = &OperationReg;

	Status = ObRegisterCallbacks(&CallbackReg, &g_pObCallbackRegHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to register object notification callback (0x&08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	return STATUS_SUCCESS;
}

VOID Unload(_In_ PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\");
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);

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

OB_PREOP_CALLBACK_STATUS ObjectNotificationCallback(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION Info)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(Info);

	return OB_PREOP_SUCCESS;
}