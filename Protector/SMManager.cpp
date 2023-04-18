#include "SMManager.h"

SMManager::SMManager(const char* name, size_t size)
{
    hMapFile = OpenFileMappingA(
        FILE_MAP_ALL_ACCESS,   // read/write access
        FALSE,                 // do not inherit the name
        name);               // name of mapping object

    if (hMapFile == NULL)
    {
        SECURITY_ATTRIBUTES secAttributes;
        secAttributes.nLength = sizeof(secAttributes);
        secAttributes.bInheritHandle = true;

        SECURITY_DESCRIPTOR secDescriptor;
        InitializeSecurityDescriptor(&secDescriptor, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&secDescriptor, TRUE, NULL, FALSE);

        secAttributes.lpSecurityDescriptor = &secDescriptor;

        hMapFile = CreateFileMappingA(
            INVALID_HANDLE_VALUE,    // use paging file
            &secAttributes,          //Everyone can access
            PAGE_READWRITE,          // read/write access
            0,                       // maximum object size (high-order DWORD)
            size,                // maximum object size (low-order DWORD)
            name);                 // name of mapping object

        if (hMapFile == NULL)
        {
            MessageBoxA(NULL, "Couldn't create or open the file mapping", "Protector", MB_ICONERROR);
            char buffer[255];
            sprintf_s(buffer, 255, "LastError : %08x", GetLastError());
            MessageBoxA(NULL, buffer, "WinAPI Error", MB_OK | MB_ICONERROR);
            return;
        }
    }
   mappedMemory = MapViewOfFile(hMapFile,   // handle to map object
        FILE_MAP_ALL_ACCESS, // read/write permission
        0,
        0,
        size);

   char buffer[256] = { 0 };
   sprintf_s(buffer, 255, "%sMutex", name);

   mutex = new WinMutex((char*)buffer);
}

void SMManager::releasePointerControl()
{
    mutex->Release();
}
