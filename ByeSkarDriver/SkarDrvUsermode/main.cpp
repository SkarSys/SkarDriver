#include "communications.h"

auto main ( ) -> int
{
	if ( bDebug ) { std::cout << " [ skardrv ] -> Debug Mode Enabled!"; }

	bool bFoundDriver = nMemmory::bFindDriver();
	if (!bFoundDriver) { if (bDebug) { std::cout << " [ error ] -> Could Not Find Driver, Exiting."; exit(1); } }
	if ( bDebug ) { std::cout << " [ skardrv ] -> Found Driver!"; }

	INT32 iProcId = nMemmory::iGetPid(L"Notepad.exe");
	if ( bDebug && iProcId > 0 ) { std::cout << " [ iNotepadPid ] -> " + iProcId; }
	else { if (bDebug)  std::cout << " [ error ] -> Could Not Get Pid"; }

	uintptr_t uNotepadBase = nMemmory::uGetImage();
	if ( bDebug && uNotepadBase > 0 ) { std::cout << " [ uNotepadBase ] -> " + uNotepadBase; }

	Sleep(-1);
	return 0;
}