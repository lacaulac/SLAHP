#pragma once
#include <Windows.h>
#include <stdio.h>
#include <aclapi.h>

//Faiblesses solution :
// Tout le monde peut utiliser l'�venement
// Fonction PulseEvent d�pr�ci�e (ne semble pas poser de souci)

class WinEvent
{
public:
	WinEvent(const char* eventName);
	void trigger(DWORD waitTime);
	void wait(DWORD waitTime);
private:
	HANDLE hEvent = NULL;
};

