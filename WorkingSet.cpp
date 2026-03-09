#include "types.h"
#include <psapi.h>
#include <vector>
#include <thread>
#include <cstdio>

#pragma comment(lib, "psapi.lib")

static volatile int watched = 0;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _MEMORY_WORKING_SET_BLOCK {
    ULONG_PTR Protection  : 5;
    ULONG_PTR ShareCount  : 3;
    ULONG_PTR Shared      : 1;
    ULONG_PTR Node        : 3;
    ULONG_PTR VirtualPage : 52;
} MEMORY_WORKING_SET_BLOCK;

typedef struct _MEMORY_WORKING_SET_INFORMATION {
    ULONG_PTR                NumberOfEntries;
    MEMORY_WORKING_SET_BLOCK WorkingSetInfo[1];
} MEMORY_WORKING_SET_INFORMATION, *PMEMORY_WORKING_SET_INFORMATION;

typedef NTSTATUS(NTAPI* pNtOpenProcess)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES*, CLIENT_ID*);
typedef NTSTATUS(NTAPI* pNtClose)(HANDLE);
typedef NTSTATUS(NTAPI* pNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef BOOL(WINAPI* pQueryWorkingSet)(HANDLE, PVOID, DWORD);
typedef BOOL(WINAPI* pEmptyWorkingSet)(HANDLE);

static pNtOpenProcess    NtOpenProcess     = nullptr;
static pNtClose          NtClose           = nullptr;
static pNtDelayExecution NtDelayExecution  = nullptr;
static pQueryWorkingSet  QueryWorkingSetFn = nullptr;
static pEmptyWorkingSet  EmptyWorkingSetFn = nullptr;

#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#define InitializeObjectAttributes(p,n,a,r,s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);     \
    (p)->RootDirectory = r;                      \
    (p)->Attributes = a;                         \
    (p)->ObjectName = n;                         \
    (p)->SecurityDescriptor = s;                 \
    (p)->SecurityQualityOfService = nullptr;     \
}

static bool InitFunctions() {
    HMODULE ntdll    = GetModuleHandleW(L"ntdll.dll");
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE psapi    = LoadLibraryW(L"psapi.dll");

    NtOpenProcess    = (pNtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
    NtClose          = (pNtClose)GetProcAddress(ntdll, "NtClose");
    NtDelayExecution = (pNtDelayExecution)GetProcAddress(ntdll, "NtDelayExecution");

    if (kernel32) {
        QueryWorkingSetFn = (pQueryWorkingSet)GetProcAddress(kernel32, "K32QueryWorkingSet");
        EmptyWorkingSetFn = (pEmptyWorkingSet)GetProcAddress(kernel32, "K32EmptyWorkingSet");
    }
    if (psapi) {
        if (!QueryWorkingSetFn)
            QueryWorkingSetFn = (pQueryWorkingSet)GetProcAddress(psapi, "QueryWorkingSet");
        if (!EmptyWorkingSetFn)
            EmptyWorkingSetFn = (pEmptyWorkingSet)GetProcAddress(psapi, "EmptyWorkingSet");
    }

    return NtOpenProcess && NtClose && NtDelayExecution &&
           QueryWorkingSetFn && EmptyWorkingSetFn;
}

static SIZE_T GetTotalEntries(HANDLE hProcess) {
    DWORD bufSize = static_cast<DWORD>(
        sizeof(MEMORY_WORKING_SET_INFORMATION) +
        8192 * sizeof(MEMORY_WORKING_SET_BLOCK));

    std::vector<Byte> buf(bufSize, static_cast<Byte>(0));
    auto* wsi = reinterpret_cast<PMEMORY_WORKING_SET_INFORMATION>(buf.data());

    while (!QueryWorkingSetFn(hProcess, wsi, static_cast<DWORD>(buf.size()))) {
        if (GetLastError() != ERROR_BAD_LENGTH) return 0;
        bufSize = static_cast<DWORD>(
            sizeof(MEMORY_WORKING_SET_INFORMATION) +
            wsi->NumberOfEntries * 2 * sizeof(MEMORY_WORKING_SET_BLOCK));
        buf.assign(bufSize, static_cast<Byte>(0));
        wsi = reinterpret_cast<PMEMORY_WORKING_SET_INFORMATION>(buf.data());
    }

    return wsi->NumberOfEntries;
}

namespace Detection {
    static void Report(SIZE_T delta) {
        printf("[DETECTION] TotalEntries delta +%llu pages\n",
               static_cast<unsigned long long>(delta));
    }
}

static void MonitorThread(HANDLE hProcess) {
    EmptyWorkingSetFn(hProcess);

    SIZE_T baseline = GetTotalEntries(hProcess);

    while (true) {
        EmptyWorkingSetFn(hProcess);

        LARGE_INTEGER interval;
        interval.QuadPart = -1000000LL;
        NtDelayExecution(FALSE, &interval);

        SIZE_T current = GetTotalEntries(hProcess);
        SIZE_T delta   = (current > baseline) ? (current - baseline) : 0;

        if (delta > 1)
            Detection::Report(delta);

        baseline = current;
    }
}

int main() {
    if (!InitFunctions()) {
        printf("[-] Failed to resolve functions\n");
        return 1;
    }

    HANDLE hProcess = nullptr;
    CLIENT_ID cid   = {};
    cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(GetCurrentProcessId()));

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

    if (!NT_SUCCESS(NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid))) {
        printf("[-] NtOpenProcess failed\n");
        return 1;
    }

    printf("WS.TotalEntries %\n\n");

    std::thread(MonitorThread, hProcess).detach();

    while (true) {
        LARGE_INTEGER interval;
        interval.QuadPart = -10000000LL;
        NtDelayExecution(FALSE, &interval);
    }

    NtClose(hProcess);
    return 0;
}
