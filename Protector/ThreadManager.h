#pragma once
#include <Windows.h>
#include <vector>

class ThreadManager
{
public:
    static std::vector<int> PauseEveryOtherThread();
    static void ResumeThreads(std::vector<int> tids);
};

