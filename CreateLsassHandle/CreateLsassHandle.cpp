#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

DWORD GetProcessID(const std::wstring& processName) {
    DWORD processID = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe)) {
        do {
            if (processName.compare(pe.szExeFile) == 0) {
                processID = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return processID;
}

int main() {
    // Get the process ID of lsass.exe
    DWORD lsassPID = GetProcessID(L"lsass.exe");
    if (lsassPID == 0) {
        std::cerr << "Failed to get the process ID of lsass.exe" << std::endl;
        return 1;
    }

    // Obtain a handle to the lsass.exe process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPID);
    if (hProcess == NULL) {
        std::cerr << "Failed to get a handle to lsass.exe. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Successfully obtained a handle to lsass.exe. Handle value: " << hProcess << std::endl;

    // Close the handle when done
    CloseHandle(hProcess);
    return 0;
}
