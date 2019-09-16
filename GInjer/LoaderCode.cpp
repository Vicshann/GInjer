
/*
  Copyright (c) 2019 Victor Sheinmann, Vicshann@gmail.com

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
  to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
*/

#include "GlobalInjector.h"

//#define NODBGLOG

#define LDRSECNAME ".loader"


#ifdef NODBGLOG
#if __has_include("LdrBinCodeRel32.cpp")
#define HAVEBINLDR32 1
#include "LdrBinCodeRel32.cpp"
#endif
#else
#if __has_include("LdrBinCodeDbg32.cpp")
#define HAVEBINLDR32 1
#include "LdrBinCodeDbg32.cpp"
#endif
#endif


#ifdef NODBGLOG
#if __has_include("LdrBinCodeRel64.cpp")
#define HAVEBINLDR64 1
#include "LdrBinCodeRel64.cpp"
#endif
#else
#if __has_include("LdrBinCodeDbg64.cpp")
#define HAVEBINLDR64 1
#include "LdrBinCodeDbg64.cpp"
#endif
#endif


#define BINKEY ((__DATE__[0] ^ (__DATE__[1] + __DATE__[2] * __DATE__[4]) ^ __DATE__[5]) + (__TIME__[0] ^ (__TIME__[1] * __TIME__[3]) ^ __TIME__[4]))     // DATE: Mmm dd yyyy  // TIME: hh:mm:ss

//---------------------------------------------------------------------------
UINT _fastcall SizeLoader32(void)
{
#ifdef HAVEBINLDR32 
 return BSizeBinLdr32;     
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
UINT _fastcall SizeLoader64(void)
{
#ifdef HAVEBINLDR64 
 return BSizeBinLdr64;
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
UINT _fastcall ReadLoader32(PBYTE DstBuf, UINT BufSize)
{
#ifdef HAVEBINLDR32     
 if(BufSize > BSizeBinLdr32)BufSize = BSizeBinLdr32;
 for(int ctr=0,bleft=BufSize;bleft > 0;ctr++,bleft--)DstBuf[ctr] = DecryptByteWithCtr(((PBYTE)&BinLdr32)[ctr],XKeyBinLdr32,bleft); 
 DBGMSG("Decrypted with %02X",BYTE(XKeyBinLdr32));
 return BufSize;
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
UINT _fastcall ReadLoader64(PBYTE DstBuf, UINT BufSize)
{
#ifdef HAVEBINLDR64    
 if(BufSize > BSizeBinLdr64)BufSize = BSizeBinLdr64;
 for(int ctr=0,bleft=BufSize;bleft > 0;ctr++,bleft--)DstBuf[ctr] = DecryptByteWithCtr(((PBYTE)&BinLdr64)[ctr],XKeyBinLdr64,bleft); 
 DBGMSG("Decrypted with %02X",BYTE(XKeyBinLdr64));
 return BufSize;
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
#ifdef _DEBUG
#pragma section(LDRSECNAME, execute, read)
#define LDRPROC __declspec(dllexport)        // Exported to keep unreferenced code
#pragma code_seg(push, LDRSECNAME)           // WARNING: Make sure that here will be no references to other sections!
#ifdef _AMD64_
namespace NLDR64
#else
namespace NLDR32
#endif
{
#ifndef NODBGLOG
_declspec(noinline) void   _cdecl MsgLogProc(char* ProcName, char* MsgFmt, ...);    
#define DBGPRNT(msg,...) MsgLogProc(ctENCSA(__FUNCTION__),ctENCSA(msg),__VA_ARGS__)        // Use encryption, else data section will be used for xmm registers with strings
#else 
#define DBGPRNT(msg,...) 
#endif
_declspec(noinline) SBlkDesc* _fastcall GetBlkDesc(void);
_declspec(noinline) SLdrDesc* _fastcall GetLdrDesc(int AWidth);
_declspec(noinline) PVOID _stdcall DoTheJob(CONTEXT*& NewThCtx, PBYTE& NtDllBase, PVOID RAddrPtr);   // Must be stdcall to keep registers free
_declspec(noinline) void _fastcall ImportFromNtDll(SLdrDesc* Desc, SNtDllProcs* NtDll);
_declspec(noinline) void _fastcall DoLoadModules(SLdrDesc* Desc, SNtDllProcs* NtDll, DWORD Flags);
_declspec(noinline) void _fastcall UnpatchNtDll(SLdrDesc* Desc, SNtDllProcs* NtDll);
_declspec(noinline) void _fastcall RemapNtDll(SLdrDesc* Desc, SNtDllProcs* NtDll);
_declspec(noinline) void _fastcall HookX32NtDll(SLdrDesc* Desc, SNtDllProcs* NtDll);
_declspec(noinline) void _fastcall RestoreLdrSystemDllInitBlock(SLdrDesc* Desc, SNtDllProcs* NtDll);
//---------------------------------------------------------------------------
//  Native x32:  BeforeX32, AfterX32
//  Native x64:  BeforeX64, AfterX64
//  WOW64: BeforeX64, BeforeX32, AfterX32   
//
// x32 fastcall stack args: NULL, NULL, CONTEXT*, NTDLL*
// x32 stdcall  stack args: CONTEXT*, NTDLL*, NULL, NULL
// x64 fastcall   reg args: CONTEXT*, NTDLL*, NULL, NULL

#pragma optimize( "yt", on )    // NOTE: Return optimized only with 'Ox' optimization
LDRPROC PVOID _fastcall AHookLdrpInitialize(CONTEXT* NewThCtx, PBYTE NtDllBase)   // Functions sorted alphabetically. This function name must start with 'A' for it to be first in the section     // Corrupts stack on x32 'stdcall' but next call is NtContinue anyway
{
 PVOID pNtUnmapViewOfSection = DoTheJob(NewThCtx, NtDllBase, _AddressOfReturnAddress());
 return ((PVOID (_fastcall*)(CONTEXT*, PBYTE))pNtUnmapViewOfSection)(NewThCtx, NtDllBase);                
}
//---------------------------------------------------------------------------
#pragma optimize( "yt", on )    // NOTE: Return optimized only with 'Ox' optimization
_declspec(noinline) SBlkDesc* _fastcall GetBlkDesc(void)
{
 return (SBlkDesc*)(((SIZE_T)_ReturnAddress()) & ~((SIZE_T)0xFFFF));
}
//---------------------------------------------------------------------------                                                   
_declspec(noinline) SLdrDesc* _fastcall GetLdrDesc(int AWidth)
{
 SBlkDesc* BDesc = GetBlkDesc();
 return (AWidth == sizeof(DWORD))?(&BDesc->LdrDesc32):(&BDesc->LdrDesc64);
}
//---------------------------------------------------------------------------
template<typename T> __forceinline T    _fastcall CharToLowCase(T val){return (((val >= 'A')&&(val <= 'Z'))?(val + 0x20):(val));}
bool _fastcall IsNamesEqualIC(char* NameA, char* NameB, UINT Len=-1)           // If templated then placed before AHookLdrInitializeThunk
{
 for(UINT ctr=0;ctr < Len;ctr++)
  {
   wchar_t ValA = CharToLowCase(NameA[ctr]);
   wchar_t ValB = CharToLowCase(NameB[ctr]);
   if(ValA != ValB)return false;
   if(!ValA)break;    // End of strings
  }
 return true;
}
//---------------------------------------------------------------------------
void*  _fastcall MemCopy(void* _Dst, const void* _Src, size_t _Size)
{
 size_t ALen = _Size/sizeof(size_t);
 size_t BLen = _Size%sizeof(size_t);
 for(size_t ctr=0;ctr < ALen;ctr++)((size_t*)_Dst)[ctr] = ((size_t*)_Src)[ctr]; 
 for(size_t ctr=(ALen*sizeof(size_t));ctr < _Size;ctr++)((char*)_Dst)[ctr] = ((char*)_Src)[ctr];  
 return _Dst;
} 
//---------------------------------------------------------------------------
_declspec(noinline) PVOID _stdcall DoTheJob(CONTEXT*& NewThCtx, PBYTE& NtDllBase, PVOID RAddrPtr)     // Should be _stdcall to spare some registers on x32
{
 SLdrDesc* LdrDesc = GetLdrDesc(sizeof(PVOID));    // Current
#ifndef _AMD64_
 if(LdrDesc->Flags & dfStdcallLdrpInit)
  {
   NewThCtx  = (CONTEXT*)((PVOID*)RAddrPtr)[1];
   NtDllBase = (PBYTE)((PVOID*)RAddrPtr)[2];
  }
#endif
 SNtDllProcs NtDll  = {0};
 LdrDesc->NtDllBase = (UINT64)NtDllBase;
 GetBlkDesc()->AddrOfContext = (UINT64)NewThCtx;
 LdrDesc->PNtDllProcs = (UINT64)&NtDll;
 ImportFromNtDll(LdrDesc, &NtDll); 
 DBGPRNT("Continue");
 if(LdrDesc->OldProtLdrInitThunk)UnpatchNtDll(LdrDesc, &NtDll);
   else RemapNtDll(LdrDesc, &NtDll);
 RestoreLdrSystemDllInitBlock(LdrDesc, &NtDll);
#ifdef _AMD64_
 if(LdrDesc->Flags & dfThisIsWow64)HookX32NtDll(LdrDesc, &NtDll);
#endif          
 DoLoadModules(LdrDesc, &NtDll, mfBeforeLdr);  // Before LdrpInit 
 DBGPRNT("Entering original LdrpInitialize"); 
#ifndef _AMD64_                                // LdrpInitialize will never return if this is x64 ntdll.dll for a WOW64 process. It will continue in x32 LdrInitializeThunk
 if(LdrDesc->Flags & dfStdcallLdrpInit)((void (_stdcall*)(PVOID, PVOID))LdrDesc->AddrOfLdrpInit)(NewThCtx,NtDllBase);      
   else 
#endif
 ((void (_fastcall*)(PVOID, PVOID))LdrDesc->AddrOfLdrpInit)(NewThCtx,NtDllBase);    // x32 else
 DBGPRNT("Finished original LdrpInitialize"); 
 DoLoadModules(LdrDesc, &NtDll, mfAfterLdr);   // After LdrpInit

 NtDllBase = (PBYTE)LdrDesc;             // Address of this mapped block // "This value can be any virtual address within the view"
 NewThCtx  = (CONTEXT*)((HANDLE)-1);     // Current process
 *(PVOID*)RAddrPtr = (PVOID)LdrDesc->LdrpInitRetAddr;    // Addr to return from NtUnmapViewOfSection
 DBGPRNT("Done");
 return NtDll.pNtUnmapViewOfSection;                                    
}
//---------------------------------------------------------------------------
// DllName Native: Kernel32.dll
// DllName WOW64: C:\Windows\SYSTEM32\wow64.dll
NTSTATUS NTAPI ProcLdrLoadDll(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle)
{  
 DBGPRNT("DllName: %ls",(DllName && DllName->Buffer)?(DllName->Buffer):(NULL));                
 SLdrDesc* LdrDesc = GetLdrDesc(sizeof(PVOID)); 
 SNtDllProcs* NtDll = (SNtDllProcs*)LdrDesc->PNtDllProcs;
 UnpatchNtDll(LdrDesc, NtDll);
 NTSTATUS res  = NtDll->pLdrLoadDll(DllPath, DllCharacteristics, DllName, DllHandle);    // Load the system dll first
 DoLoadModules(LdrDesc, NtDll, mfBeforeLdr|mfAfterLdr);         // Special 'BeforeLdr' where LdrLoadDll is safe to use
 DBGPRNT("Done");
 return res;
}
//---------------------------------------------------------------------------
_declspec(noinline) void _fastcall SetHookLdrLoadDll(SLdrDesc* Desc, SNtDllProcs* NtDll)
{
 DBGPRNT("Enter");
 ULONG  PrevProt    = 0;
 SIZE_T RegionSize  = sizeof(Desc->OrigLdrInitThunk);
 PVOID  BaseAddress = NtDll->pLdrLoadDll;
 MemCopy(&Desc->OrigLdrInitThunk, BaseAddress, RegionSize);      // Reusing the buffer
 NtDll->pNtProtectVirtualMemory((HANDLE)-1, &BaseAddress, &RegionSize, PAGE_EXECUTE_READWRITE, &PrevProt);
 BYTE  Patch[]   = {0x68,0,0,0,0,0xC3};    // push XXXXXXXX; ret    // Target block is in 2GB
 DWORD Offset    = ((UINT64)&ProcLdrLoadDll - (UINT64)&AHookLdrpInitialize); 
 *(PDWORD)&Patch[1] = Desc->LdrProcAddr + Offset;
 MemCopy(NtDll->pLdrLoadDll, &Patch, sizeof(Patch));    
 Desc->OldProtLdrInitThunk = PrevProt;
 Desc->AddrOfLdrInitThunk  = (UINT64)NtDll->pLdrLoadDll;
 DBGPRNT("Done: Offset=%p, Address=%08X",Offset,*(PDWORD)&Patch[1]);
}
//---------------------------------------------------------------------------
_declspec(noinline) SModDesc* _fastcall GetNextModule(SModDesc* Curr, bool SkipLoaded)   // Skips mfModLoaded
{
 if(!Curr)
  {
   SBlkDesc* BDesc = GetBlkDesc(); 
   if(!BDesc->ModDescLstOffs)return NULL;     // No modules!
   Curr = (SModDesc*)&((PBYTE)BDesc)[BDesc->ModDescLstOffs];     // First
  }
   else
    {
     if(!Curr->NextOffs)return NULL;  // No more modules
     Curr = (SModDesc*)&((PBYTE)Curr)[Curr->NextOffs];           // Next
    }
 DWORD SkipMsk = (sizeof(PVOID)==4)?(mfModuleX64):(mfModuleX32);
 if(SkipLoaded)SkipMsk |= mfModLoaded;
 while(Curr->Flags & SkipMsk)
  {
   if(!Curr->NextOffs)return NULL;  // No more modules
   Curr = (SModDesc*)&((PBYTE)Curr)[Curr->NextOffs];             // Next
  }
 return Curr;
}
//---------------------------------------------------------------------------
// Exact - mask must match exactly else just to result nonzero (One of flags present)
_declspec(noinline) int _fastcall CountModulesByMask(SLdrDesc* Desc, DWORD Mask, bool Exact) 
{
 int Count = 0;
 for(SModDesc* Mod=GetNextModule(NULL,true);Mod;Mod=GetNextModule(Mod,true))
  {
   if(Exact)
    {
     if((Mod->Flags & Mask) != Mask)continue;  // Not all flags present
    }
     else
      {
       if(!(Mod->Flags & Mask))continue;  // None of flags present
      }
   Count++;
  }
 return Count;
}
//---------------------------------------------------------------------------
_declspec(noinline) void _fastcall LoadModulesNormal(SLdrDesc* Desc, SNtDllProcs* NtDll, DWORD Flags)
{
 DBGPRNT("Enter: Flags=%08X",Flags);
 for(SModDesc* Mod=GetNextModule(NULL,true);Mod;Mod=GetNextModule(Mod,true))
  {
   if(Mod->Flags & mfReflLoad)continue;
   if((Mod->Flags & Flags) != Flags)continue;

   UNICODE_STRING uni;
   uni.Buffer = Mod->ModulePath;
   uni.Length = Mod->PathSize * sizeof(WCHAR);
   uni.MaximumLength = uni.Length + sizeof(WCHAR);

   PVOID hLib = NULL;
   DBGPRNT("Loading %08X: %ls",Mod->Flags,uni.Buffer);
   Mod->Flags |= mfModLoaded;      // Do not try to load it again
   NtCurrentTeb()->LastErrorValue = (DWORD)Mod;
   NTSTATUS res = NtDll->pLdrLoadDll(NULL, 0, &uni, &hLib);
   DBGPRNT("res=%08X, Handle=%p",res,hLib);
  }
 DBGPRNT("Done");
}
//---------------------------------------------------------------------------
// Find entry point address in an unmapped DLL
/*_declspec(noinline) PVOID _fastcall GetRawDllEntry(PBYTE RawModBase)   // Unused because of PE header encryption 
{
 DOS_HEADER  *DosHdr = (DOS_HEADER*)RawModBase;
 if((DosHdr->FlagMZ != SIGN_MZ)){DBGPRNT("Invalid MZ: %p",RawModBase); return NULL;}
 WIN_HEADER<PECURRENT> *WinHdr = (WIN_HEADER<PECURRENT>*)&RawModBase[DosHdr->OffsetHeaderPE];
 if((WinHdr->FlagPE != SIGN_PE)){DBGPRNT("Invalid PE: %p",RawModBase); return NULL;}
 UINT HdrLen = DosHdr->OffsetHeaderPE+WinHdr->FileHeader.HeaderSizeNT+sizeof(FILE_HEADER)+sizeof(DWORD);
 SECTION_HEADER *CurSec = (SECTION_HEADER*)&RawModBase[HdrLen];
 DWORD EPRva = WinHdr->OptionalHeader.EntryPointRVA;
 for(int ctr = 0;ctr < WinHdr->FileHeader.SectionsNumber;ctr++,CurSec++)
  {
   if((CurSec->SectionRva > EPRva)||((CurSec->SectionRva+CurSec->VirtualSize) <= EPRva))continue;
   EPRva -= CurSec->SectionRva;
   if(EPRva >= CurSec->PhysicalSize)return NULL;  // Not present in the file as physical
   return &RawModBase[CurSec->PhysicalOffset + EPRva];
  }
 return NULL;
}*/
//---------------------------------------------------------------------------
_declspec(noinline) void _fastcall LoadModulesReflective(SLdrDesc* Desc, SNtDllProcs* NtDll, DWORD Flags)
{
 DBGPRNT("Enter: Flags=%08X",Flags);
 for(SModDesc* Mod=GetNextModule(NULL,true);Mod;Mod=GetNextModule(Mod,true))
  {
   if(!(Mod->Flags & mfReflLoad))continue;
   if((Mod->Flags & Flags) != Flags)continue;
   if(!Mod->ModEPOffs){DBGPRNT("No EP for module: %ls",&Mod->ModulePath);}
   PVOID EPAddr = (PVOID)(Mod->ModuleBase + Mod->ModEPOffs);          // GetRawDllEntry((PBYTE)Mod->ModuleBase);
   DBGPRNT("Loading %08X %08X: %ls",Mod->Flags,EPAddr,&Mod->ModulePath); 
   Mod->Flags |= mfModLoaded;      // Do not try to load it again
   NtCurrentTeb()->LastErrorValue = (DWORD)Mod;
   BOOL res = ((BOOL (APIENTRY*)(HMODULE, DWORD, LPVOID))EPAddr)((HMODULE)Mod->ModuleBase, DLL_REFLECTIVE_LOAD, Mod);
   DBGPRNT("res=%08X",res);
  }
  DBGPRNT("Done");
}
//---------------------------------------------------------------------------
_declspec(noinline) void _fastcall DoLoadModules(SLdrDesc* Desc, SNtDllProcs* NtDll, DWORD Flags)
{
 DBGPRNT("Enter: Flags=%08X",Flags);
 if(Flags & mfAfterLdr)
  {
   DWORD BaseFlg     = (Flags & mfBeforeLdr)?(mfBeforeLdr):(mfAfterLdr);     // In case it is called from ProcLdrLoadDll
   DWORD MskRefLoad  = BaseFlg|mfReflLoad;
   DWORD ModsRefLoad = CountModulesByMask(Desc, MskRefLoad, true);
   DBGPRNT("MskRefLoad=%08X, ModsRefLoad=%u",MskRefLoad, ModsRefLoad);
   if(ModsRefLoad)LoadModulesReflective(Desc, NtDll, MskRefLoad);  // Do reflective load
   DWORD MskLdrLoad  = BaseFlg;
   DWORD ModsLdrLoad = CountModulesByMask(Desc, MskLdrLoad, true);
   DBGPRNT("MskLdrLoad=%08X, ModsLdrLoad=%u",MskLdrLoad,ModsLdrLoad);
   if(ModsLdrLoad)LoadModulesNormal(Desc, NtDll, MskLdrLoad);      // Do normal load
  }
 if(Flags & mfBeforeLdr)      // NOTE: LdrLoadDll doesn`t work at this stage
  {
   DWORD MskBeforeInit  = mfBeforeLdr|mfBeforeInit|mfReflLoad;
   DWORD ModsBeforeInit = CountModulesByMask(Desc, MskBeforeInit, true);
   DBGPRNT("ModsBeforeInit=%u",ModsBeforeInit);
   if(ModsBeforeInit)LoadModulesReflective(Desc, NtDll, MskBeforeInit);  // Do reflective load
   DWORD ModsBeforeLdr  = CountModulesByMask(Desc, mfBeforeLdr, true);   // Load rest of modules mfBeforeLdr
   DBGPRNT("ModsBeforeLdr=%u",ModsBeforeLdr);
   if(ModsBeforeLdr)SetHookLdrLoadDll(Desc, NtDll);   // Will continue when the process finishes initialization
  }
 DBGPRNT("Done");
}
//---------------------------------------------------------------------------
_declspec(noinline) void _fastcall UnpatchNtDll(SLdrDesc* Desc, SNtDllProcs* NtDll)
{
 if(!Desc->OldProtLdrInitThunk)return;
 DBGPRNT("Unpatching original ntdll.dll");
 ULONG  PrevProt    = 0;
 SIZE_T RegionSize  = sizeof(Desc->OrigLdrInitThunk);
 PVOID  BaseAddress = (PVOID)Desc->AddrOfLdrInitThunk;
 MemCopy(BaseAddress, &Desc->OrigLdrInitThunk, RegionSize);    
 NtDll->pNtProtectVirtualMemory((HANDLE)-1, &BaseAddress, &RegionSize, Desc->OldProtLdrInitThunk, &PrevProt);
 Desc->OldProtLdrInitThunk = 0;
 DBGPRNT("Done");
}
//---------------------------------------------------------------------------
_declspec(noinline) void _fastcall RemapNtDll(SLdrDesc* Desc, SNtDllProcs* NtDll)
{  
 UNICODE_STRING PathStr;
 OBJECT_ATTRIBUTES ObjAttrs;                    
 SBlkDesc* BDesc = GetBlkDesc();   
 DBGPRNT("Mapping original ntdll.dll back");
 ctOENCSW(L"\\KnownDlls\\ntdll.dll", sKnownNtDll);   // Always native
      
 ObjAttrs.Length = sizeof(OBJECT_ATTRIBUTES);
 ObjAttrs.Attributes = OBJ_CASE_INSENSITIVE;
 ObjAttrs.RootDirectory = 0;
 ObjAttrs.SecurityDescriptor = NULL;
 ObjAttrs.SecurityQualityOfService = NULL;
 ObjAttrs.ObjectName = &PathStr;
                  
 PathStr.Buffer = sKnownNtDll.Decrypt();     // If missing then this is a native x32 system 
 PathStr.Length = (sKnownNtDll.Size()-1) * sizeof(WCHAR);      // Size includes Zero byte
 PathStr.MaximumLength = PathStr.Length+sizeof(WCHAR);

 HANDLE hSection = NULL;
 NTSTATUS stat   = NtDll->pNtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_MAP_WRITE, &ObjAttrs);
 if(stat){DBGPRNT("NtOpenSection failed with %08X",stat); return;}
 stat   = ((decltype(NtDll->pNtUnmapViewOfSection))&BDesc->CodeNtUnmapViewOfSection)((HANDLE)-1, (PVOID)Desc->NtDllBase);   // Unmap our shared memory with a temporary ntdll.dll 
 if(stat){DBGPRNT("NtUnmapViewOfSection failed with %08X",stat); NtDll->pNtClose(hSection); return;}
 PVOID  BaseAddr = (PVOID)Desc->NtDllBase;
 SIZE_T viewSize = 0;
 stat   = ((decltype(NtDll->pNtMapViewOfSection))&BDesc->CodeNtMapViewOfSection)(hSection, (HANDLE)-1, (PVOID*)&BaseAddr, 0, 0, NULL, (SIZE_T*)&viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);  // Map the real NtDll.dll     // ViewUnmap ?
 if(stat){DBGPRNT("NtMapViewOfSection failed with %08X",stat);}
 NtDll->pNtClose(hSection);
 DBGPRNT("Done");
}
//---------------------------------------------------------------------------
#ifdef _AMD64_
_declspec(noinline) void _fastcall HookX32NtDll(SLdrDesc* Desc, SNtDllProcs* NtDll)  
{
 SLdrDesc* LdrDesc = GetLdrDesc(sizeof(DWORD));    // x32
 if(!LdrDesc->Flags){DBGPRNT("No WOW64 x32 ntdll.dll to hook(This is native process)"); return;}      // Do nothing if there is no modules for x32
 DBGPRNT("Hooking WOW64 x32 ntdll.dll");   
 BYTE Patch[]  = {0x50,0x68,0,0,0,0,0xC3};    // push eax; push XXXXXXXX; ret    // Target block is in 2GB
 *(PDWORD)&Patch[2] = LdrDesc->LdrProcAddr;
 UINT64 PatchAddr   = LdrDesc->LdrpInitRetAddr - 5;    // call rel
 ULONG  PrevProt    = 0;
 SIZE_T RegionSize  = sizeof(Patch);
 PVOID  BaseAddress = (PVOID)PatchAddr;  
 NtDll->pNtProtectVirtualMemory((HANDLE)-1, &BaseAddress, &RegionSize, PAGE_EXECUTE_READWRITE, &PrevProt);
 MemCopy((PVOID)PatchAddr, &Patch, sizeof(Patch));    
 LdrDesc->OldProtLdrInitThunk = PrevProt;                 
 GetBlkDesc()->AddrOfLdrSystemDllInitBlock = 0;  // Not required anymore
 DBGPRNT("Done");                   
}
#endif
//---------------------------------------------------------------------------
_declspec(noinline) void _fastcall RestoreLdrSystemDllInitBlock(SLdrDesc* Desc, SNtDllProcs* NtDll) 
{
 SBlkDesc* BDesc = GetBlkDesc();  
 if(!BDesc->AddrOfLdrSystemDllInitBlock || ((DWORD*)BDesc->AddrOfLdrSystemDllInitBlock)[1]){DBGPRNT("Not required"); return;}    
 DBGPRNT("Restoring original LdrSystemDllInitBlock(Above Windows 7)");               
 ULONG  PrevProt    = 0;
 SIZE_T RegionSize  = *(DWORD*)&BDesc->LdrSystemDllInitBlock;
 PVOID  BaseAddress = (PVOID)BDesc->AddrOfLdrSystemDllInitBlock;
 NtDll->pNtProtectVirtualMemory((HANDLE)-1, &BaseAddress, &RegionSize, PAGE_READWRITE, &PrevProt);
 MemCopy((PVOID)BDesc->AddrOfLdrSystemDllInitBlock, &BDesc->LdrSystemDllInitBlock, *(DWORD*)&BDesc->LdrSystemDllInitBlock);    
 NtDll->pNtProtectVirtualMemory((HANDLE)-1, &BaseAddress, &RegionSize, PrevProt, &PrevProt);
 DBGPRNT("Done");
}
//---------------------------------------------------------------------------
_declspec(noinline) void _fastcall ImportFromNtDll(SLdrDesc* Desc, SNtDllProcs* NtDll)
{
 ctOENCSA("NtClose",                sNtClose);
 ctOENCSA("LdrLoadDll",             sLdrLdDll);
 ctOENCSA("NtProtectVirtualMemory", sNtProtectVirtualMemory);
 ctOENCSA("NtWriteVirtualMemory",   sNtWriteVirtualMemory);
 ctOENCSA("NtOpenSection",          sNtOpenSection);
 ctOENCSA("NtMapViewOfSection",     sNtMapViewOfSection);
 ctOENCSA("NtUnmapViewOfSection",   sNtUnmapViewOfSection);
#ifndef NODBGLOG                               
 ctOENCSA("NtWriteFile",         sNtWriteFile);
 ctOENCSA("vsprintf",            sVSprintf);
 LPSTR nVSprintf               = sVSprintf.Decrypt();
 LPSTR nNtWriteFile            = sNtWriteFile.Decrypt();
#endif
 LPSTR nNtClose                = sNtClose.Decrypt();
 LPSTR nLdrLdDll               = sLdrLdDll.Decrypt();
 LPSTR nNtProtectVirtualMemory = sNtProtectVirtualMemory.Decrypt();
 LPSTR nNtWriteVirtualMemory   = sNtWriteVirtualMemory.Decrypt();
 LPSTR nNtOpenSection          = sNtOpenSection.Decrypt();
 LPSTR nNtMapViewOfSection     = sNtMapViewOfSection.Decrypt();
 LPSTR nNtUnmapViewOfSection   = sNtUnmapViewOfSection.Decrypt();
 PBYTE NtDllBase               = (PBYTE)Desc->NtDllBase;
 DOS_HEADER* DosHdr            = (DOS_HEADER*)NtDllBase;
 WIN_HEADER<PECURRENT>* WinHdr = (WIN_HEADER<PECURRENT>*)&NtDllBase[DosHdr->OffsetHeaderPE];
 DATA_DIRECTORY* ExportDir     = &WinHdr->OptionalHeader.DataDirectories.ExportTable;
 EXPORT_DIR* Export            = (EXPORT_DIR*)&NtDllBase[ExportDir->DirectoryRVA];
                   
 PDWORD NamePointers = (PDWORD)&NtDllBase[Export->NamePointersRVA];
 PDWORD AddressTable = (PDWORD)&NtDllBase[Export->AddressTableRVA];
 PWORD  OrdinalTable = (PWORD )&NtDllBase[Export->OrdinalTableRVA];
 for(UINT ctr=0,idx=0;(ctr < Export->NamePointersNumber) && (idx < 7);ctr++)  // By name
  {      
   DWORD nrva  = NamePointers[ctr];   
   if(!nrva)continue;
   SIZE_T Ordinal = OrdinalTable[ctr];      // Name Ordinal 
   if(!NtDll->pNtClose && IsNamesEqualIC(nNtClose, (LPSTR)&NtDllBase[nrva]))*(PVOID*)&NtDll->pNtClose = &NtDllBase[AddressTable[Ordinal]];
   if(!NtDll->pLdrLoadDll && IsNamesEqualIC(nLdrLdDll, (LPSTR)&NtDllBase[nrva]))*(PVOID*)&NtDll->pLdrLoadDll = &NtDllBase[AddressTable[Ordinal]];
   if(!NtDll->pNtUnmapViewOfSection && IsNamesEqualIC(nNtUnmapViewOfSection, (LPSTR)&NtDllBase[nrva]))*(PVOID*)&NtDll->pNtUnmapViewOfSection = &NtDllBase[AddressTable[Ordinal]];
   if(!NtDll->pNtProtectVirtualMemory && IsNamesEqualIC(nNtProtectVirtualMemory, (LPSTR)&NtDllBase[nrva]))*(PVOID*)&NtDll->pNtProtectVirtualMemory = &NtDllBase[AddressTable[Ordinal]];
   if(!NtDll->pNtWriteVirtualMemory && IsNamesEqualIC(nNtWriteVirtualMemory, (LPSTR)&NtDllBase[nrva]))*(PVOID*)&NtDll->pNtWriteVirtualMemory = &NtDllBase[AddressTable[Ordinal]];
   if(!NtDll->pNtOpenSection && IsNamesEqualIC(nNtOpenSection, (LPSTR)&NtDllBase[nrva]))*(PVOID*)&NtDll->pNtOpenSection = &NtDllBase[AddressTable[Ordinal]];
   if(!NtDll->pNtMapViewOfSection && IsNamesEqualIC(nNtMapViewOfSection, (LPSTR)&NtDllBase[nrva]))*(PVOID*)&NtDll->pNtMapViewOfSection = &NtDllBase[AddressTable[Ordinal]];
#ifndef NODBGLOG            
   if(!NtDll->pNtWriteFile && IsNamesEqualIC(nNtWriteFile, (LPSTR)&NtDllBase[nrva]))*(PVOID*)&NtDll->pNtWriteFile = &NtDllBase[AddressTable[Ordinal]];
   if(!NtDll->pVSprintf && IsNamesEqualIC(nVSprintf, (LPSTR)&NtDllBase[nrva]))*(PVOID*)&NtDll->pVSprintf = &NtDllBase[AddressTable[Ordinal]];
#endif
  } 
 DBGPRNT("Done");
}
//---------------------------------------------------------------------------
#ifndef NODBGLOG
_declspec(noinline) void   _cdecl MsgLogProc(char* ProcName, char* MsgFmt, ...)
{
 struct ST     // To avoid import of 'sprintf'
  {  
   static int _cdecl Format(SNtDllProcs* NtDll, char* OutBuf, ...)  
    {
     va_list args;
     va_start(args,OutBuf);
     int res = NtDll->pVSprintf(OutBuf,ctENCSA("%08X%08X %06X:%06X %s -> "),args);
     va_end(args);
     return res;
    }
  };
 va_list args;
 SBlkDesc* BlkDesc = GetBlkDesc();
 if(!BlkDesc->hDbgLogOutA && !BlkDesc->hDbgLogOutB)return;
#ifdef _AMD64_
 SNtDllProcs* NtDll = (SNtDllProcs*)BlkDesc->LdrDesc64.PNtDllProcs;
#else
 SNtDllProcs* NtDll = (SNtDllProcs*)BlkDesc->LdrDesc32.PNtDllProcs;
#endif 
 char Buffer[1025];
 va_start(args,MsgFmt);
 TEB* teb = NtCurrentTeb();                                                 
 int LenA = ST::Format(NtDll, Buffer, SharedUserData->SystemTime.High1Time,SharedUserData->SystemTime.LowPart, (DWORD)teb->ClientId.UniqueProcess, (DWORD)teb->ClientId.UniqueThread, ProcName); 
 int LenB = NtDll->pVSprintf(&Buffer[LenA],MsgFmt,args);
 UINT DSize = LenA+LenB;
 Buffer[DSize++] = '\r';
 Buffer[DSize++] = '\n';
 va_end(args);
 IO_STATUS_BLOCK IoStatusBlock = {0};
 NTSTATUS stat;
 if(BlkDesc->hDbgLogOutA)stat = NtDll->pNtWriteFile((HANDLE)BlkDesc->hDbgLogOutA,NULL,NULL,NULL,&IoStatusBlock,&Buffer,DSize,NULL,NULL);
 if(BlkDesc->hDbgLogOutB)stat = NtDll->pNtWriteFile((HANDLE)BlkDesc->hDbgLogOutB,NULL,NULL,NULL,&IoStatusBlock,&Buffer,DSize,NULL,NULL);
}
//---------------------------------------------------------------------------
#endif
}
#pragma code_seg( pop )

int _fastcall GenerateBinLdr(void)
{
#ifdef NODBGLOG
#ifdef _AMD64_
 char    BinLdrName[] = {"BinLdr64"};
 wchar_t DstPath[] = {_L(PROJECT_DIR) L"LdrBinCodeRel64.cpp"};      
#else
 char    BinLdrName[] = {"BinLdr32"};
 wchar_t DstPath[] = {_L(PROJECT_DIR) L"LdrBinCodeRel32.cpp"};     
#endif
#else
#ifdef _AMD64_
 char    BinLdrName[] = {"BinLdr64"};
 wchar_t DstPath[] = {_L(PROJECT_DIR) L"LdrBinCodeDbg64.cpp"};      
#else
 char    BinLdrName[] = {"BinLdr32"};
 wchar_t DstPath[] = {_L(PROJECT_DIR) L"LdrBinCodeDbg32.cpp"};     
#endif
#endif
 char KeyLine[128];
 CArr<BYTE> DstFile;
 SECTION_HEADER* Sec = NULL;
 PBYTE ModBase = (PBYTE)GetModuleHandleA(NULL);
 if(!GetModuleSection(ModBase, LDRSECNAME, &Sec)){DBGMSG("No loader section found!"); return -1;}
 UINT SecLen = (Sec->VirtualSize + 15) & ~0xF;  // It is equal to exact size of code
 BYTE XorKey = BINKEY;
 int llen = wsprintfA(KeyLine,"#define XKey%s  0x%02X\r\n",&BinLdrName,XorKey);
 DstFile.Append((PBYTE)&KeyLine, llen);
 if(BinDataToCArray(DstFile, &ModBase[Sec->SectionRva], SecLen, BinLdrName, XorKey, sizeof(DWORD)) <= 0){LOGMSG("Failed to create BinLdr file!"); return -2;}
 DstFile.ToFile(DstPath);
 LOGMSG("Saved BinLdr %02X: %ls",XorKey,&DstPath);
 return 0;
}
//---------------------------------------------------------------------------
#endif