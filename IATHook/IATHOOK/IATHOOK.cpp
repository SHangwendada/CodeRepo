#include <Windows.h>
#include <cstdio>

typedef int(__cdecl* PMemcmp)(const void* buf1, const void* buf2, size_t count);

DWORD GetMemcmpAddressFromIAT() {
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) {
        printf("Failed to get handle of current module\n");
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) & (pNTHeader->OptionalHeader);
    PIMAGE_IMPORT_DESCRIPTOR pIMPORT_DESCRIPTOR = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hModule + pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pIMPORT_DESCRIPTOR->FirstThunk) {
        PDWORD FirstThunk = (PDWORD)((DWORD)hModule + pIMPORT_DESCRIPTOR->FirstThunk);
        PDWORD OriginalFirstThunk = (PDWORD)((DWORD)hModule + pIMPORT_DESCRIPTOR->OriginalFirstThunk);
        while (*FirstThunk) {
            char* functionName = (char*)((*OriginalFirstThunk) + (DWORD)hModule + 2);
            if (strcmp(functionName, "memcmp") == 0) {
                return (DWORD)FirstThunk;
            }
            FirstThunk++;
            OriginalFirstThunk++;
        }
        pIMPORT_DESCRIPTOR++;
    }

    printf("Failed to find memcmp in IAT.\n");
    return 0;
}

int __cdecl MyMemcmp(const void* buf1, const void* buf2, size_t count) {
    printf("Hooked memcmp Param: buf1: %p, buf2: %p, count: %zu\n", buf1, buf2, count);

    PMemcmp OriginalMemcmp = (PMemcmp)GetProcAddress(GetModuleHandleA("ucrtbase.dll"), "memcmp");
    if (!OriginalMemcmp) {
        printf("Failed to call original memcmp.\n");
        return -1;
    }
    int result = OriginalMemcmp(buf1, buf2, count);

    printf("Original memcmp result: %d\n", result);
    return result;
}

void InstallIatHook(DWORD* pdwOldFunction, DWORD dwNewFunction) {
    DWORD dwOldProtect;
    if (VirtualProtect(pdwOldFunction, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect)) {
        *pdwOldFunction = dwNewFunction;
        VirtualProtect(pdwOldFunction, sizeof(DWORD), dwOldProtect, &dwOldProtect);
        printf("Function hooked successfully.\n");
    }
    else {
        printf("Failed to change protection of IAT.\n");
    }
}

int main(int argc, char* argv[]) {
    DWORD* dwMemcmp = (DWORD*)GetMemcmpAddressFromIAT();
    if (dwMemcmp == 0) {
        printf("Failed to get memcmp address from IAT.\n");
        return -1;
    }

    printf("memcmp address in IAT: %p\n", (void*)*dwMemcmp);

    InstallIatHook(dwMemcmp, (DWORD)MyMemcmp);

    char buf1[] = "test1";
    char buf2[] = "test2";
    memcmp(buf1, buf2, sizeof(buf1));

    // Uncomment below to uninstall the hook
    // UninstallIatHook(dwMemcmp, (DWORD)MyMemcmp);
    // memcmp(buf1, buf2, sizeof(buf1));

    return 0;
}
