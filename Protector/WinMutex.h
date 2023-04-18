#pragma once
#include <Windows.h>
#include <string.h>
#include <stdio.h>

class WinMutex
{
private:
	HANDLE hMutex;
public:
	WinMutex(char* mutexName);
	void Lock();
	void Release();
};

