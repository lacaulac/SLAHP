#include <iostream>
#include <Windows.h>

BYTE* getOffsetForString(BYTE* data, size_t dataLength, BYTE* buffer, DWORD bufferLength);

LPCWSTR domainStr = L"####TARGETDOMAIN";
LPCWSTR urlStr = L"####TARGETURL_PADDING";
LPCSTR pathStr = "####TARGETPATH_PADDING";
LPCSTR pubkeyStr = "####TARGETPUBKEY";
LPCSTR optionsStr = "####OPTIONS_PADDING";

int main(int argc, char** argv)
{
    char allUsageBuffer[MAX_PATH] = { '\0' };
    if (argc < 5)
    {
        printf("Usage: %s <appName> <targetPath> <domain> <urlpath> [<pubkeyPath>] [<iconPath> <rceditPath>] [<enableCache> <enableMultiProcess> <hideFromUser>]\n", argv[0]);
        printf("\tUsing a custom icon requires rcedit (https://github.com/electron/rcedit)");
        return 1;
    }
    //Create the folder
    sprintf_s(allUsageBuffer, MAX_PATH, "mkdir Launcher-%s", argv[1]);
    system(allUsageBuffer);
    sprintf_s(allUsageBuffer, MAX_PATH, "del \"Launcher-%s\\%s Launcher.exe\"", argv[1], argv[1]);
    system(allUsageBuffer);
    sprintf_s(allUsageBuffer, MAX_PATH, "del Launcher-%s\\ProtectorAgent.dll", argv[1]);
    system(allUsageBuffer);
    {
        //Read orig DLL
        HANDLE dllHandle = CreateFileA("ProtectorAgent.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); // https://docs.microsoft.com/en-us/windows/win32/fileio/opening-a-file-for-reading-or-writing
        if (dllHandle == INVALID_HANDLE_VALUE)
        {
            sprintf_s(allUsageBuffer, MAX_PATH, "CreateFileA error: %u", GetLastError());
            MessageBoxA(NULL, allUsageBuffer, "LauncherCreater", MB_OK | MB_ICONERROR);
            ExitProcess(1);
        }
        DWORD fileSize = GetFileSize(dllHandle, NULL);
        BYTE* buffer = (BYTE*)malloc(fileSize);
        if (ReadFile(dllHandle, buffer, fileSize, NULL, NULL) == false)
        {
            sprintf_s(allUsageBuffer, MAX_PATH, "ReadFile error: %u", GetLastError());
            MessageBoxA(NULL, allUsageBuffer, "LauncherCreater", MB_OK | MB_ICONERROR);
            CloseHandle(dllHandle);
            ExitProcess(1);
        }
        CloseHandle(dllHandle);

        //Patch DLL
        LPWSTR domainPtr = (LPWSTR)getOffsetForString((BYTE*)domainStr, wcslen(domainStr) * sizeof(wchar_t), buffer, fileSize);
        if (domainPtr == NULL)
        {
            MessageBoxA(NULL, "Couldn't get the domain placeholder's address", "LauncherCreater", MB_OK | MB_ICONERROR);
            ExitProcess(1);
        }
        MultiByteToWideChar(CP_ACP, 0, argv[3], -1, domainPtr, MAX_PATH);
        LPWSTR urlPtr = (LPWSTR)getOffsetForString((BYTE*)urlStr, wcslen(urlStr) * sizeof(wchar_t), buffer, fileSize);
        if (domainPtr == NULL)
        {
            MessageBoxA(NULL, "Couldn't get the domain placeholder's address", "LauncherCreater", MB_OK | MB_ICONERROR);
            ExitProcess(1);
        }
        MultiByteToWideChar(CP_ACP, 0, argv[4], -1, urlPtr, MAX_PATH);
        if (argc >= 6) //If a public key file was provided
        {
            printf("Adding a public key.\n");
            FILE* tmpFile = NULL;
            char pubKeyBuffer[2048] = { '\0' };
            const char* namePubKeyFile = argv[5];
            fopen_s(&tmpFile, namePubKeyFile, "rb");
            fseek(tmpFile, 0, SEEK_END);
            long keySize = ftell(tmpFile);
            fseek(tmpFile, 0, SEEK_SET);
            fread(pubKeyBuffer, keySize, 1, tmpFile);
            fclose(tmpFile);
            std::string pubKeyB64(pubKeyBuffer);

            LPSTR pubKeyPtr = (LPSTR)getOffsetForString((BYTE*)pubkeyStr, strlen(pubkeyStr), buffer, fileSize);
            strcpy_s(pubKeyPtr, 512, pubKeyB64.c_str());
            printf("Public key added!\n");
        }
        if (argc >= 11)
        {
            bool useCache = (strcmp(argv[8], "true") == 0);
            bool useMultiProc = (strcmp(argv[9], "true") == 0);
            bool hideFromUser = (strcmp(argv[10], "true") == 0);
            LPSTR optionsPtr = (LPSTR)getOffsetForString((BYTE*)optionsStr, strlen(optionsStr), buffer, fileSize);
            sprintf_s(optionsPtr, 5, "%c%c%c", (useCache ? 'y' : 'n'), (useMultiProc ? 'y' : 'n'), (hideFromUser ? 'y' : 'n'));
        }
        else if (argc > 8 && argc < 11)
        {
            printf("You need to provide all options at once !\n");
            ExitProcess(255);
        }
        else
        {
            LPSTR optionsPtr = (LPSTR)getOffsetForString((BYTE*)optionsStr, strlen(optionsStr), buffer, fileSize);
            sprintf_s(optionsPtr, 5, "nnn");
        }

        //Write DLL to folder
        sprintf_s(allUsageBuffer, MAX_PATH, "Launcher-%s/ProtectorAgent.dll", argv[1]);
        dllHandle = CreateFileA(allUsageBuffer, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL); // https://docs.microsoft.com/en-us/windows/win32/fileio/opening-a-file-for-reading-or-writing
        if (dllHandle == INVALID_HANDLE_VALUE)
        {
            sprintf_s(allUsageBuffer, MAX_PATH, "CreateFileA error: %u", GetLastError());
            MessageBoxA(NULL, allUsageBuffer, "LauncherCreater", MB_OK | MB_ICONERROR);
        }
        if (WriteFile(dllHandle, buffer, fileSize, NULL, NULL) == false)
        {
            sprintf_s(allUsageBuffer, MAX_PATH, "WriteFile error: %u", GetLastError());
            MessageBoxA(NULL, allUsageBuffer, "LauncherCreater", MB_OK | MB_ICONERROR);
        }
        CloseHandle(dllHandle);
        free(buffer);
    }
    {
        //Read orig Launcher
        HANDLE dllHandle = CreateFileA("ProtectedLauncher.exe", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); // https://docs.microsoft.com/en-us/windows/win32/fileio/opening-a-file-for-reading-or-writing
        if (dllHandle == INVALID_HANDLE_VALUE)
        {
            sprintf_s(allUsageBuffer, MAX_PATH, "CreateFileA error: %u", GetLastError());
            MessageBoxA(NULL, allUsageBuffer, "LauncherCreater", MB_OK | MB_ICONERROR);
        }
        DWORD fileSize = GetFileSize(dllHandle, NULL);
        BYTE* buffer = (BYTE*)malloc(fileSize);
        if (ReadFile(dllHandle, buffer, fileSize, NULL, NULL) == false)
        {
            sprintf_s(allUsageBuffer, MAX_PATH, "ReadFile error: %u", GetLastError());
            MessageBoxA(NULL, allUsageBuffer, "LauncherCreater", MB_OK | MB_ICONERROR);
        }
        CloseHandle(dllHandle);
        //Patch Launcher
        LPSTR pathPtr = (LPSTR)getOffsetForString((BYTE*)pathStr, strlen(pathStr) * sizeof(char), buffer, fileSize);
        strcpy_s(pathPtr, MAX_PATH, argv[2]);
        //Write Launcher to folder
        sprintf_s(allUsageBuffer, MAX_PATH, "Launcher-%s/ProtectedLauncher.exe", argv[1]);
        dllHandle = CreateFileA(allUsageBuffer, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL); // https://docs.microsoft.com/en-us/windows/win32/fileio/opening-a-file-for-reading-or-writing
        if (dllHandle == INVALID_HANDLE_VALUE)
        {
            sprintf_s(allUsageBuffer, MAX_PATH, "CreateFileA error: %u", GetLastError());
            MessageBoxA(NULL, allUsageBuffer, "LauncherCreater", MB_OK | MB_ICONERROR);
        }
        if (WriteFile(dllHandle, buffer, fileSize, NULL, NULL) == false)
        {
            sprintf_s(allUsageBuffer, MAX_PATH, "WriteFile error: %u", GetLastError());
            MessageBoxA(NULL, allUsageBuffer, "LauncherCreater", MB_OK | MB_ICONERROR);
        }
        CloseHandle(dllHandle);
        free(buffer);
        if (argc >= 8)
        {
            char cmdLine[256] = { 0 };
            sprintf_s(cmdLine, 255, "%s Launcher-%s\\ProtectedLauncher.exe --set-icon \"%s\"", argv[7], argv[1], argv[6]);
            system(cmdLine);
        }
    }
    sprintf_s(allUsageBuffer, 259, "move Launcher-%s\\ProtectedLauncher.exe \"Launcher-%s\\%s Launcher.exe\"", argv[1], argv[1], argv[1]);
    system(allUsageBuffer);
}

BYTE* getOffsetForString(BYTE* data, size_t dataLength, BYTE* buffer, DWORD bufferLength)
{
    BYTE* currentBaseOffset = NULL;
    int dataProgression = 0;
    for (int i = 0; i < bufferLength; i++)
    {
        BYTE currentByte = buffer[i];
        if (dataProgression == dataLength)
        {
            return currentBaseOffset;
        }
        if (currentByte != *(BYTE*)(((char*)(data)) + dataProgression))
        {
            currentBaseOffset = NULL;
            dataProgression = 0;
        }
        else
        {
            if (currentBaseOffset == NULL)
            {
                currentBaseOffset = &(buffer[i]);
            }
            dataProgression++;
        }
    }
    return NULL;
}
