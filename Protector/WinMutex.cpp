#include "WinMutex.h"

WinMutex::WinMutex(char* mutexName)
{
    hMutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, mutexName);

    if (hMutex == NULL)
    {
        SECURITY_ATTRIBUTES secAttributes;
        secAttributes.nLength = sizeof(secAttributes);
        secAttributes.bInheritHandle = true;

        SECURITY_DESCRIPTOR secDescriptor;
        InitializeSecurityDescriptor(&secDescriptor, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&secDescriptor, TRUE, NULL, FALSE);

        secAttributes.lpSecurityDescriptor = &secDescriptor;

        hMutex = CreateMutexA(&secAttributes, FALSE, mutexName);


        if (hMutex == NULL)
        {
            char errMsg[512] = { 0 };
            sprintf_s(errMsg, 511, "Couldn't create or open the mutex %s", mutexName);
            MessageBoxA(NULL, errMsg, "Protector", MB_ICONERROR);
            char buffer[255];
            sprintf_s(buffer, 255, "LastError : %08x", GetLastError());
            MessageBoxA(NULL, buffer, "WinAPI Error", MB_OK | MB_ICONERROR);
            return;
        }
        else
        {
            printf("Created mutex %s\n", mutexName);
        }
    }
    else
    {
        printf("Opened mutex %s\n", mutexName);
    }
}

void WinMutex::Lock()
{
    WaitForSingleObject(hMutex, INFINITE);
}

void WinMutex::Release()
{
    ReleaseMutex(hMutex);
}
