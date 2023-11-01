# KernelObjectNotificationDemo

Demonstration of registering a kernel object notification.

## Enumerating Object Notification Callbacks in WinDbg

WindDbg can be used to traverse object manager datastructures and examine how the callback is registered. In driver code, the registration of a object notification for handle creation or duplication is registered to the `Process` object type:

```C
OperationReg.ObjectType = PsProcessType;
OperationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
OperationReg.PreOperation = ObjectNotificationCallback;
```

In WinDbg, we can find the addresses of the managers Object Types and examine the instance of the `Process` object type
```
kd> !object \ObjectTypes

Object: ffffdd8f8bc059e0  Type: (ffffb881b7883bf0) Directory
    ObjectHeader: ffffdd8f8bc059b0 (new version)
    HandleCount: 0  PointerCount: 69
    Directory Object: ffffdd8f8bc92e20  Name: ObjectTypes

    Hash Address          Type                      Name
    ---- -------          ----                      ----
     00  ffffb881b78fea60 Type                      TmTm
     01  ffffb881b78fe4e0 Type                      Desktop
         ffffb881b785d8a0 Type                      Process

kd> dt nt!_OBJECT_TYPE ffffb881b785d8a0

   +0x000 TypeList         : _LIST_ENTRY [ 0xffffb881`b785d8a0 - 0xffffb881`b785d8a0 ]
   +0x010 Name             : _UNICODE_STRING "Process"
   +0x020 DefaultObject    : (null) 
   +0x028 Index            : 0x7 ''
   +0x02c TotalNumberOfObjects : 0x91
   +0x030 TotalNumberOfHandles : 0x5b5
   +0x034 HighWaterNumberOfObjects : 0x9e
   +0x038 HighWaterNumberOfHandles : 0x625
   +0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
   +0x0b8 TypeLock         : _EX_PUSH_LOCK
   +0x0c0 Key              : 0x636f7250
   +0x0c8 CallbackList     : _LIST_ENTRY [ 0xffffdd8f`8d0c2e00 - 0xffffdd8f`8d0c2e00 ]
```

The `CallbackList` field is a linked list.


We can loop through this list and find our callback. First, we need to identify our callback address:
```
0: kd> x KernelObjectNotificationDemo!ObjectNotificationCallback
fffff801`2d701040 KernelObjectNotificationDemo!ObjectNotificationCallback (void *, struct _OB_PRE_OPERATION_INFORMATION *)
```

## Debugging Shortcut Command Reference

### Map Driver Files 
```
.kdfiles -m C:\Users\debugee\source\repos\KernelObjectNotificationDemo\KernelObjectNotificationDemo\x64\Debug\filemap.txt
```

### Break on Driver Entry
```
bu KernelObjectNotificationDemo!DriverEntry
```

### Start Driver
```
.shell -ci "start cmd.exe /c sc start KernelObjectNotificationDemo & pause" cmd.exe
```

### Altogether

```
.kdfiles -m C:\Users\debugee\source\repos\KernelObjectNotificationDemo\KernelObjectNotificationDemo\x64\Debug\filemap.txt

bu KernelObjectNotificationDemo!DriverEntry

.shell -ci "start cmd.exe /c sc start KernelObjectNotificationDemo & pause" cmd.exe
```
## References

- https://www.unknowncheats.me/forum/anti-cheat-bypass/355581-win7-win10-obregistercallbacks-bypass.html