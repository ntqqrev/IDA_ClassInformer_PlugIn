
// Virtual function table parsing support
#pragma once

namespace vftable
{
	// vftable info container
	struct vtinfo
	{
		ea_t start, end; // union { EA_32 ea_t} addresses
		int  methodCount;
		//char name[MAXSTR];
	};
	BOOL getTableInfo(ea_t ea, vtinfo &info);

	// Returns TRUE if mangled name prefix indicates a vftable
	inline BOOL isValid(LPCSTR name){ return(*((PDWORD) name) == 0x375F3F3F /*"??_7"*/); }
}
