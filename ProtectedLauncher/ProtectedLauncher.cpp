#include <iostream>
#include "../Protector/framework.h"

const char* targetPath = "####TARGETPATH_PADDING_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA####";

int main(int argc, char** argv)
{
#ifdef _DEBUG
    system("PAUSE");
#endif
    if (targetPath[0] == '#' && targetPath[1] == '#')
    {
        MessageBoxA(NULL, "This launcher is unpatched. This means it doesn't even know what program it's supposed to protect.", "ProtectedLauncher", MB_OK | MB_ICONERROR);
        ExitProcess(420);
    }
    //targetPath = "C:\\Users\\Programmation\\AppData\\Roaming\\Spotify\\Spotify.exe";
    InitProtector(L"HijackProtector", L"lacaulac.ovh", L"/stage3a/protected_launcher.cfg", true, true, "UlNBMQAIAAADAAAAAAEAAAAAAAAAAAAAAQABv65V7AiIxjmiz4l2xv3srLSF/ZZMv6M9nEWRIu0iRit4+rCNrsIONr/p94dwteHsUHUR6IZ+sh931uDGjl3tO35zw5oI6TfQcVOi020sa56yY2N2PgC/zuTgsgmKKC2+P783MvhRjVriCMzF7+MRhSUZWODJF+VXbZavAT2jffnPR3sP3yVGb13k6Jji04N5Ix1RJzVjl3+0E1w9Vs+tpq3RNlywfQqA0XOVMryPIFhffT2Zt3hgTBfSaPXcgdy+MCoJJ67PjR+LrbTHAAvKZcawTnT0Gl/OKlMTmhWLv+MoQIPj4qn0F6D3+xIJb2kjg4yx4QJslqgeULITBbw3QQ==", true, false, false);
    //CreateSuspendedProcess
    size_t bufferSize = 1024 * sizeof(char);
    char* binaryCmdlineBuffer = (char*)calloc(1, bufferSize);
    if (binaryCmdlineBuffer == NULL)
    {
        MessageBoxA(NULL, "Couldn't allocate path buffer", "ProtectedLauncher", MB_OK | MB_ICONERROR);
        return 0;
    }
    ExpandEnvironmentStringsA(targetPath, binaryCmdlineBuffer, 1023);
    //strcpy_s(binaryCmdlineBuffer, 1023, targetPath);

    //Get the app's folder
    char childCurrentDirectory[MAX_PATH] = { 0 };
    strcpy_s(childCurrentDirectory, MAX_PATH - 1, binaryCmdlineBuffer);
    for (int i = strlen(childCurrentDirectory) - 1; i > 0; i--)
    {
        if (childCurrentDirectory[i] == '\\')
        {
            childCurrentDirectory[i + 1] = '\0';
            break;
        }
    }

    for (int i = 1; i < argc; i++)
    {
        sprintf_s(binaryCmdlineBuffer + strlen(binaryCmdlineBuffer), bufferSize - strlen(binaryCmdlineBuffer), " %s", argv[i]);
    }
    
    char srcDll[MAX_PATH + 1] = { 0 };
    char dstDll[MAX_PATH + 1] = { 0 };
    GetCurrentDirectoryA(MAX_PATH, srcDll);
    sprintf_s(srcDll, MAX_PATH, "%s\\ProtectorAgent.dll", srcDll);
    sprintf_s(dstDll, MAX_PATH, "%sProtectorAgent.dll", childCurrentDirectory);
    //Copy ourselves into the target folder
    CopyFileA(srcDll, dstDll, false);

    

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD pid;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessA(NULL, binaryCmdlineBuffer, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, childCurrentDirectory, &si, &pi) == false)
    {
        MessageBoxA(NULL, "Couldn't create the target process", "ProtectedLauncher", MB_OK | MB_ICONERROR);
        return -1;
    }
    pid = pi.dwProcessId;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    //Inject into suspended process

    const char* libPath = "ProtectorAgent.dll";
    HANDLE procHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, false, pid);
    if (procHandle == NULL)
    {
        MessageBoxA(NULL, "Couldn't get access to the target process", "ProtectedLauncher", MB_OK | MB_ICONERROR);
        return -1;
    }

    PVOID dllNameAdr = VirtualAllocEx(procHandle, NULL, strlen(libPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (dllNameAdr == NULL)
    {
        MessageBoxA(NULL, "Couldn't allocate memory in the target process", "ProtectedLauncher", MB_OK | MB_ICONERROR);
        return -1;
    }

    if (WriteProcessMemory(procHandle, dllNameAdr, libPath, strlen(libPath) + 1, NULL) == NULL)
    {
        MessageBoxA(NULL, "Couldn't allocate write into the target process's memory", "ProtectedLauncher", MB_OK | MB_ICONERROR);
        return -1;
    }

    HANDLE tHandle = CreateRemoteThread(procHandle, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), dllNameAdr, 0, 0);
    if (tHandle == NULL)
    {
        MessageBoxA(NULL, "Couldn't create remote thread", "ProtectedLauncher", MB_OK | MB_ICONERROR);
        return -1;
    }
}