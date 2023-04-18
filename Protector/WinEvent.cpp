#include "WinEvent.h"

/// Creates a WinEvent objects. Creates or opens the event, depending on its previous existence
WinEvent::WinEvent(const char* eventName)
{
	hEvent = OpenEventA(EVENT_ALL_ACCESS, FALSE, eventName);
	if (hEvent == NULL)
	{
		SECURITY_ATTRIBUTES secAttributes;
		secAttributes.nLength = sizeof(secAttributes);
		secAttributes.bInheritHandle = true;

		SECURITY_DESCRIPTOR secDescriptor;
		InitializeSecurityDescriptor(&secDescriptor, SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(&secDescriptor, TRUE, NULL, FALSE);

		secAttributes.lpSecurityDescriptor = &secDescriptor;

		hEvent = CreateEventA(&secAttributes, TRUE, FALSE, eventName);
		if (hEvent == NULL)
		{
			char buffer[255];
			sprintf_s(buffer, 255, "LastError : %08x", GetLastError());
			MessageBoxA(NULL, buffer, "WinAPI Error", MB_OK | MB_ICONERROR);
#ifdef _DEBUG
			DebugBreak();
#endif
		}
		else
			printf("Created event !\n");
	}
	else
	{
		printf("Opened event !\n");
	}
}

/// Trigger the event
void WinEvent::trigger(DWORD waitTime)
{
	//SetEvent(hEvent);
	PulseEvent(hEvent); //FIXME Deprecated, but couldn't replace it
	//printf("Set the event !\n");
	//Sleep(waitTime); //FIXME BAAAAAAAAAAAAAAAAAAAAD
	//ResetEvent(hEvent);
}

/// Wait for the event
void WinEvent::wait(DWORD waitTime)
{
	//printf("Waiting for event !\n");
	WaitForSingleObject(hEvent, INFINITE);
	//Sleep(waitTime); //FIXME BAAAAAAAAAAAAAAAAAAAAD
	//printf("Event got triggered !\n");
}
