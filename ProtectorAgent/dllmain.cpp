// dllmain.cpp : Définit le point d'entrée de l'application DLL.
#include "framework.h"
#include "../detours.h"
#include "../Protector/framework.h"

#include <tlhelp32.h>
#include <tchar.h>
#include <winternl.h>

LPCWSTR targetDomain = L"####TARGETDOMAIN_PADDING_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA####";
LPCWSTR targetURL = L"####TARGETURL_PADDING_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA####";
LPCSTR targetPubKey = "####TARGETPUBKEY_PADDING_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA####";
LPCSTR options = "####OPTIONS_PADDING_AAAAAAAAAAA####";
HANDLE hThreadSnap = INVALID_HANDLE_VALUE;

WCHAR currentExe[MAX_PATH * 2] = { '\0' };

typedef BOOL(WINAPI* tCreateProcessInternalW)(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken);
BOOL WINAPI hkCreateProcessInternalW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken);
tCreateProcessInternalW oCreateProcessInternalW = (tCreateProcessInternalW)DetourFindFunction("KernelBase.dll", "CreateProcessInternalW");

LPCWSTR getFileNameFromPath(LPCWSTR path);
bool isSameExecutable(LPCWSTR path1, LPCWSTR path2);
DWORD GetIntegrityLevel(HANDLE hToken);

DWORD WINAPI ProtectionThread(LPVOID param)
{
    //This ifdef is only defined when debugging
    //MessageBoxA(NULL, "Hello world.", "ProtectedLauncher", MB_OK | MB_ICONERROR);
#ifdef _CRT_SECURE_NO_WARNINGS
    char logFileName[255];
    sprintf_s(logFileName, 255, "logstdout_%u.log", GetCurrentThreadId());
    freopen(logFileName, "wb", stdout);
#endif
    GetModuleFileNameW(NULL, currentExe, MAX_PATH * 2);
    if ((targetDomain[0] == '#' && targetDomain[1] == '#') || (targetURL[0] == '#' && targetURL[1] == '#'))
    {
        MessageBoxA(NULL, "This agent is unpatched! This means it doesn't know where to fetch its configuration file from.", "ProtectedLauncher", MB_OK | MB_ICONERROR);
        ExitProcess(420);
    }
    LPCSTR keyValue = (targetPubKey[0] == '#' && targetPubKey[1] == '#') ? NULL : targetPubKey;

    bool useCache = options[0] == 'y';
    bool useMultiProc = options[1] == 'y';
    bool hideFromUser = options[2] == 'y';


    InitProtector(L"HijackProtector", targetDomain, targetURL, true, true, keyValue, useCache, useMultiProc, hideFromUser);
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LoadLibraryA("KernelBase.dll");
    DetourAttach(&(PVOID&)oCreateProcessInternalW, hkCreateProcessInternalW);
    DetourTransactionCommit();
    //Resume other threads
    THREADENTRY32 te32;

    // Take a snapshot of all running threads  
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return 1;

    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32);

    // Retrieve information about the first thread,
    // and exit if unsuccessful
    if (!Thread32First(hThreadSnap, &te32))
    {
        CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
        return 1;
    }

    // Now walk the thread list of the system,
    // and display information about each thread
    // associated with the specified process
    do
    {
        if (te32.th32OwnerProcessID == GetCurrentProcessId())
        {
            //Get a handle on the thread with ThreadResume rights
            HANDLE threadHandle = NULL;
            threadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (threadHandle != NULL) //If we got a valid handle
            {
                //Resume the thread
                ResumeThread(threadHandle);
                //Close the handle
                CloseHandle(threadHandle);
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));

    //  Don't forget to clean up the snapshot object.
    CloseHandle(hThreadSnap);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, ProtectionThread, NULL, NULL, NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

BOOL __stdcall hkCreateProcessInternalW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken)
{
    //MessageBoxW(NULL, lpCommandLine, lpApplicationName, MB_OK);
#ifdef _CRT_SECURE_NO_WARNINGS
    DWORD integrityLevel = GetIntegrityLevel(hToken);

    /*char buffer[1024] = { '\0' };
    sprintf_s(buffer, 1023, "Integrity level for handle %p\nLevel: %08x", hToken, integrityLevel);
    MessageBoxA(NULL, buffer, "Protector Error", MB_OK);*/

    if (integrityLevel <= SECURITY_MANDATORY_LOW_RID || ((!(isSameExecutable(lpApplicationName, currentExe))) && (!(isSameExecutable(lpCommandLine, currentExe)))))
    {
        //MessageBoxA(NULL, "Skipping start injection.", "Protector debug", MB_OK);
        //MessageBoxW(NULL, L"Not gonna attach", lpCommandLine, MB_OK);
        return oCreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
        //PTOKEN_MANDATORY_LABEL integrityInfo;
        //DWORD structSize = 0;
        //GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &structSize);
        //integrityInfo = (PTOKEN_MANDATORY_LABEL)malloc(structSize);
        //if (GetTokenInformation(hToken, TokenIntegrityLevel, &integrityInfo, structSize, &structSize))
        //{
        //    DWORD tmpVal = (DWORD)(UCHAR)(*GetSidSubAuthorityCount(integrityInfo->Label.Sid) - 1);
        //    MessageBoxA(NULL, "Survived first step", "TokenIntegrityLevel", MB_OK);
        //    DWORD dwIntegrityLevel = *GetSidSubAuthority(integrityInfo->Label.Sid, tmpVal);
        //    /*char buff[255] = { '\0' };
        //    sprintf_s(buff, 254, "Token integrity level: %u", dwIntegrityLevel);
        //    MessageBoxA(NULL, buff, "TokenIntegrityLevel", MB_OK | MB_ICONINFORMATION);*/
        //    free(integrityInfo);
        //}
        //free(integrityInfo);



        //TODO Recouper avec https://stackoverflow.com/q/12774738
        // Et aussi avec le code dans la solution poubelle CPPTests




    }
#endif
    char sendBuffer[MAX_PATH];
    LPPROCESS_INFORMATION procInfo = lpProcessInformation;
    bool allocOwnProcInfo = lpProcessInformation == NULL;
    if (allocOwnProcInfo)
    {
        procInfo = (LPPROCESS_INFORMATION)malloc(sizeof(PROCESS_INFORMATION));
    }
    //Call the original function with a PROCESS_INFORMATION structure we can access after the call is made
    auto ret = oCreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, procInfo, hNewToken);
    //Get the PID
    DWORD pid = procInfo->dwProcessId;

    if (allocOwnProcInfo)
    {
        free(procInfo);
    }

    //Inject ourselves into the newly created process
    const char libPath[] = "ProtectorAgent.dll";
    HANDLE procHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, false, pid);
    if (procHandle == NULL)
    {
        DWORD error = GetLastError();
        sprintf_s(sendBuffer, MAX_PATH, "[%u;%u]Error while opening %u's process: %u\n", GetCurrentProcessId(), GetCurrentThreadId(), pid, error);
        MessageBoxA(NULL, sendBuffer, "ProtectorAgent", MB_OK | MB_ICONERROR);
        return ret;
    }

    PVOID dllNameAdr = VirtualAllocEx(procHandle, NULL, strlen(libPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (dllNameAdr == NULL)
    {
        DWORD error = GetLastError();
        sprintf_s(sendBuffer, MAX_PATH, "[%u;%u]Error while allocating memory inside of %u: %u\n", GetCurrentProcessId(), GetCurrentThreadId(), pid, error);
        MessageBoxA(NULL, sendBuffer, "ProtectorAgent", MB_OK | MB_ICONERROR);
        return ret;
    }

    if (WriteProcessMemory(procHandle, dllNameAdr, libPath, strlen(libPath) + 1, NULL) == NULL)
    {
        DWORD error = GetLastError();
        sprintf_s(sendBuffer, MAX_PATH, "[%u;%u]Error while writing to %u's memory : %u\n", GetCurrentProcessId(), GetCurrentThreadId(), pid, error);
        MessageBoxA(NULL, sendBuffer, "ProtectorAgent", MB_OK | MB_ICONERROR);
        return ret;
    }

    HANDLE tHandle = CreateRemoteThread(procHandle, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), dllNameAdr, 0, 0);
    if (tHandle == NULL)
    {
        DWORD error = GetLastError();
        sprintf_s(sendBuffer, MAX_PATH, "[%u;%u]Error while creating remote thread: %u\n", GetCurrentProcessId(), GetCurrentThreadId(), error);
        MessageBoxA(NULL, sendBuffer, "ProtectorAgent", MB_OK | MB_ICONERROR);
    }

    return ret;
}

LPCWSTR getFileNameFromPath(LPCWSTR path)
{
    if (path == NULL)
        return NULL;
    LPWSTR fileName = (LPWSTR)path;
    LPWSTR tmp = NULL;
    while ((tmp = wcsstr(fileName, L"\\")) && tmp < wcsstr(fileName, L".exe"))
    {
        fileName = tmp + 1;
    }
    return fileName;
}

bool isSameExecutable(LPCWSTR path1, LPCWSTR path2)
{
    wchar_t restoreFirst = '\0';
    if(path1 != NULL)
        if (wcsstr(path1, L".exe") != NULL)
        {
            restoreFirst = *(wcsstr(path1, L".exe") + 4);
            *(LPWSTR)(wcsstr(path1, L".exe") + 4) = '\0';
        }
    wchar_t restoreSecond = '\0';
    if (path1 != NULL)
        if (wcsstr(path2, L".exe") != NULL)
        {
            restoreSecond = *(wcsstr(path2, L".exe") + 4);
            *(LPWSTR)(wcsstr(path2, L".exe") + 4) = '\0';
        }
    path1 = getFileNameFromPath(path1);
    if (path1 == NULL)
        return false;
    path2 = getFileNameFromPath(path2);
    if (path2 == NULL)
        return false;
    bool comparison = _wcsicmp(path1, path2) == 0;
    if (restoreFirst != '\0')
    {
        *(LPWSTR)(wcsstr(path1, L".exe") + 4) = restoreFirst;
    }

    if (restoreSecond != '\0')
    {
        *(LPWSTR)(wcsstr(path2, L".exe") + 4) = restoreSecond;
    }
    return comparison;
}

DWORD GetIntegrityLevel(HANDLE hToken)
{
    if (hToken == NULL)
        hToken = GetCurrentProcessToken();
    PTOKEN_MANDATORY_LABEL integrityInfo;
    DWORD structSize = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &structSize);
    integrityInfo = (PTOKEN_MANDATORY_LABEL)malloc(structSize);
    if (GetTokenInformation(hToken, TokenIntegrityLevel, integrityInfo, structSize, &structSize))
    {
        PSID sid = (PSID)integrityInfo->Label.Sid;
        bool isValid = IsValidSid(sid);
        BYTE* authCount = (GetSidSubAuthorityCount(sid));
        DWORD dwIntegrityLevel = *GetSidSubAuthority(sid, (*authCount) - 1);
        //free(integrityInfo);
        //TODO Memory leak here (free(integrityInfo) crashes for some forsaken reason)
        
        return dwIntegrityLevel;
        /*char buff[255] = { '\0' };
        sprintf_s(buff, 254, "Token integrity level: %u", dwIntegrityLevel);
        MessageBoxA(NULL, buff, "TokenIntegrityLevel", MB_OK | MB_ICONINFORMATION);*/
    }
    else
    {
        DWORD lastError = GetLastError();
        char buffer[255] = { '\0' };
        sprintf_s(buffer, 254, "Couldn't retrieve the integrity level for handle %p\nError(dec): %u", hToken, lastError);
        MessageBoxA(NULL, buffer, "Protector Error", MB_OK | MB_ICONERROR);
        free(integrityInfo);
        return 0;
    }
}
