#include <Windows.h>
#include <fstream>
#include <string>
#include <vector>

#include <MinHook.h>
#include <Hooking.Patterns.h>

std::vector<int> g_dlcList;

int bStringHash( const char *a1 )
{
	const char *v1; // edx
	unsigned __int8 v2; // cl
	int result; // eax

	v1 = a1;
	v2 = *a1;
	for ( result = -1; v2; ++v1 )
	{
		result = v2 + 33 * result;
		v2 = v1[1];
	}
	return result;
}

bool __fastcall UnlockSystem_IsDLCUnlock( void *_this, void *_edx, int unlock )
{
	// Check if we have the specified unlock in dlc.txt.
	return ( std::find( g_dlcList.begin(), g_dlcList.end(), unlock ) != g_dlcList.end() );
}

bool __cdecl ISelectablePart_CheckOnlineParts( void *carPart )
{
	// This function hides Xbox 360 exclusive Virus vinyls.
	// We replace it with a stub that always returns true to unhide them.
	if ( carPart == NULL )
		return false;

	return true;
}

void Initialize()
{
	// Read the list of unlocks.
	std::ifstream file( "dlc.txt" );
	if ( !file.is_open() )
		return;

	std::string str;
	while ( std::getline( file, str ) )
	{
		if ( str.empty() )
			continue;

		g_dlcList.push_back( bStringHash( str.c_str() ) );
	}

	if ( MH_Initialize() != MH_OK )
		return;

	// Locate the functions we need to hook in the game code.
	auto pattern_IsDLCUnlock = hook::pattern( "56 8B 71 10 85 F6 74 1B 8B 51 14 33 C0 85 D2 76 12 8B CE 8B 74 24 08" );
	if ( pattern_IsDLCUnlock.empty() )
		return;

	auto pattern_CheckOnlineParts = hook::pattern( "56 8B 74 24 08 85 F6 75 04 32 C0 5E C3 57 68 ? ? ? 00 E8" );
	if ( pattern_CheckOnlineParts.empty() )
		return;

	if ( MH_CreateHook( pattern_IsDLCUnlock.get_first(), &UnlockSystem_IsDLCUnlock, NULL ) != MH_OK )
		return;

	if ( MH_CreateHook( pattern_CheckOnlineParts.get_first(), &ISelectablePart_CheckOnlineParts, NULL ) != MH_OK )
		return;

	if ( MH_EnableHook( MH_ALL_HOOKS ) != MH_OK )
		return;
}

BOOL WINAPI DllMain( HINSTANCE /*hinstDLL*/, DWORD fdwReason, LPVOID /*lpvReserved*/ )
{
	switch ( fdwReason )
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_DETACH:
		default:
			break;
	}
	return TRUE;
}

extern "C" __declspec( dllexport ) void InitializeASI()
{
	Initialize();
}
