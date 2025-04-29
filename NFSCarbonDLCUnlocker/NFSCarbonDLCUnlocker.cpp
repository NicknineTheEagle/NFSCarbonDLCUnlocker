#include <Windows.h>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>

#include <MinHook.h>
#include <Hooking.Patterns.h>

HMODULE g_module = NULL;
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

bool g_initialized = false;

void Initialize()
{
	if ( g_initialized )
		return;

	g_initialized = true;

	WCHAR pathStr[MAX_PATH];
	GetModuleFileNameW( g_module, pathStr, ARRAYSIZE( pathStr ) );
	std::filesystem::path modulePath( pathStr );

	// Read the list of unlocks.
	std::ifstream file( modulePath.parent_path() / L"dlc.txt" );
	if ( !file.is_open() )
		return;

	std::string str;
	while ( std::getline( file, str ) )
	{
		if ( str.empty() )
			continue;

		g_dlcList.push_back( bStringHash( str.c_str() ) );
	}

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

void *( WINAPI *Direct3DCreate9_orig )( UINT ) = NULL;
void *Direct3DCreate9_target = NULL;

void *WINAPI Direct3DCreate9_hook( UINT SDKVersion )
{
	void *result = Direct3DCreate9_orig( SDKVersion );

	Initialize();

	return result;
}

extern "C" __declspec( dllexport ) void InitializeASI()
{
	// SafeDisc executables are encrypted so we can't insert our hooks just yet.
	// Create an early hook that lets us know when the game code has finished decrypting.
	MH_Initialize();
	MH_CreateHookApiEx( L"d3d9", "Direct3DCreate9", &Direct3DCreate9_hook, (void **)&Direct3DCreate9_orig, &Direct3DCreate9_target );
	MH_EnableHook( Direct3DCreate9_target );
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID /*lpvReserved*/ )
{
	switch ( fdwReason )
	{
		case DLL_PROCESS_ATTACH:
			g_module = hinstDLL;
			break;
		case DLL_THREAD_ATTACH:
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_DETACH:
		default:
			break;
	}
	return TRUE;
}
