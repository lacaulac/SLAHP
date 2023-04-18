#include "ThreadManager.h"
#include <TlHelp32.h>

std::vector<int> ThreadManager::PauseEveryOtherThread()
{
    std::vector<int> threadIDs;
    int PID = GetCurrentProcessId();
    int currentTID = GetCurrentThreadId();
    //Based off https://stackoverflow.com/a/1206915
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(h, &te)) {
            do {
                if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                    sizeof(te.th32OwnerProcessID)) {
                    if (te.th32OwnerProcessID == PID && te.th32ThreadID != currentTID)
                    {
                        threadIDs.push_back(te.th32ThreadID);
                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                        SuspendThread(hThread);
                        CloseHandle(hThread);
                    }
                }
                te.dwSize = sizeof(te);
            } while (Thread32Next(h, &te));
        }
        CloseHandle(h);
    }
    else
    {
        int lastError = GetLastError();
        NOP_FUNCTION;
    }
	return threadIDs;
}

void ThreadManager::ResumeThreads(std::vector<int> tids)
{
    for(int tid : tids)
    {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        ResumeThread(hThread);
        CloseHandle(hThread);
    }
}
