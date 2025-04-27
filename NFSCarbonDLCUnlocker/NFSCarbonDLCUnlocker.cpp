#include <Windows.h>
#include <fstream>
#include <string>
#include <vector>

#include <MinHook.h>

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

	if ( MH_CreateHook( (LPVOID)0x00820280, &UnlockSystem_IsDLCUnlock, NULL ) != MH_OK )
		return;

	if ( MH_CreateHook( (LPVOID)0x00577620, &ISelectablePart_CheckOnlineParts, NULL ) != MH_OK )
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
