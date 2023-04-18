#pragma once
class NotificationSystem
{

};

enum class PROTECTION_ACTION {
	QUIT,
	RELOAD,
	IGNORE_ALERT
};

typedef struct {
	unsigned int Initialization; //Should be 0xDEADBEEF once initialised
	int InitiatorThreadId;
	int InitiatorProcessId;
	int alertAmount;
	PROTECTION_ACTION ProtectionAction;
} ProtectorSharedActionState;