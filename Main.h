
// Class Informer
#pragma once


extern BOOL getVerifyEa(ea_t ea, ea_t &rValue);
extern BOOL hasAnteriorComment(ea_t ea);
extern void addTableEntry(UINT32 flags, ea_t vft, int methodCount, LPCSTR format, ...);
extern BOOL getPlainTypeName(__in LPCSTR mangled, __out_bcount(MAXSTR) LPSTR outStr);

extern void fixDword(ea_t ea);
extern void fixEa(ea_t ea);
extern void fixFunction(ea_t eaFunc);

extern void setName(ea_t ea, __in LPCSTR name);
extern void setComment(ea_t ea, LPCSTR comment, BOOL rptble);
extern void setAnteriorComment(ea_t ea, const char *format, ...);
inline void setUnknown(ea_t ea, int size) {	del_items(ea, DELIT_EXPAND, size); }

// Return TRUE if there is a name at address that is not a dumbly name
inline BOOL hasName(ea_t ea) { return has_name(get_flags(ea)); }

// Return TRUE if there is a comment at address
inline BOOL hasComment(ea_t ea) { return has_cmt(get_flags(ea)); }

// Get IDA 32 bit value with IDB existence verification
template <class T> BOOL getVerify32(ea_t eaPtr, T& rValue)
{
	// Location valid?
	if (IS_VALID_ADDR(eaPtr))
	{
		// Get 32bit value
		rValue = (T) get_32bit(eaPtr);
		return TRUE;
	}
	return FALSE;
}

// Segment cache container
const UINT32 _CODE_SEG = (1 << 0);
const UINT32 _DATA_SEG = (1 << 1);
struct SEGMENT
{
	ea_t start, end;  // Start and end VA of the segment
	UINT32 type;      // Either SEG_CODE, SEG_DATA, or both for the corner case of a IDB with just one segment.
	char name[8 + 1]; // PE header format is 8 max
};
extern const SEGMENT *FindCachedSegment(ea_t addr);

extern BOOL g_optionPlaceStructs;
