/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_KernelObjectNotificationDemo,
    0xa695d651,0xa29f,0x4eba,0xa8,0x78,0xf2,0x98,0x99,0x49,0x87,0x55);
// {a695d651-a29f-4eba-a878-f29899498755}
