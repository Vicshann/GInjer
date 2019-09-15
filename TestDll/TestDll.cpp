
/*
  Copyright (c) 2018 Victor Sheinmann, Vicshann@gmail.com

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
  to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
*/

#include "TestDll.h"

//====================================================================================
#pragma comment(linker,"/ENTRY:DLLMain")
#pragma comment(linker,"/NODEFAULTLIB")

// ---------- SETTINGS ------------------

                         
//---------------------------------------
// NtCurrentTeb()->LastErrorValue = SInjModDesc*  (Always fits into 32 bits, valid if > 65535)

// Reflective load:
//     hModule    = Module Base
//     ReasonCall = 15
//     lpReserved = SInjModDesc*  (Can be used to find SBlkDescr*)
//===========================================================================
BOOL APIENTRY DLLMain(HMODULE hModule, DWORD ReasonCall, LPVOID lpReserved) 
{
 SModDesc* ModDesc = ModDescFromCurTh();        // NULL if loaded not by GInjer
 SBlkDesc* BlkDesc = AddrToBlkDesc(ModDesc);
 SLdrDesc* LdrDesc = GetCurLdrDesc(BlkDesc); 
 bool RemTh = (DWORD)hModule & InjLdr::RemThModMarker;      // DLLMain has been passed to CreateRemoteThread. Normal HMODULE would be aligned at 0x1000  
 if(RemTh || (ReasonCall >= DLL_REFLECTIVE_LOAD)) 
  {
   hModule    = (HMODULE)InjLdr::ReflectiveRelocateSelf(hModule, (LdrDesc)?((PVOID)LdrDesc->NtDllBase):(NULL));                           
   ReasonCall = DLL_PROCESS_ATTACH;   
  } 
 if(ModDesc){LdrLogInit(ModDesc); LDRLOG("Hello from %08X: %ls", ModDesc->Flags, &ModDesc->ModulePath);}
 switch(ReasonCall)	    
  {			 
   case DLL_PROCESS_ATTACH:
     break;									
   case DLL_THREAD_ATTACH:
     break; 
   case DLL_THREAD_DETACH:
     break;
   case DLL_PROCESS_DETACH:       
	 break;
   case DLL_REFLECTIVE_LOAD:  
     break;

   default : return false;  // WRONG REASON CODE !!!!!!
  }
 return true;
}
//====================================================================================

//====================================================================================
