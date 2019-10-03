
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


#if __has_include("DrvBin32.cpp")
#define HAVEBINDRV32 1
#include "DrvBin32.cpp"     // SHA1 and SHA256 signed
#endif

#if __has_include("DrvBin64.cpp")
#define HAVEBINDRV64 1
#include "DrvBin64.cpp"     // SHA1 and SHA256 signed
#endif

#define BINKEY ((__DATE__[0] ^ (__DATE__[1] - __DATE__[2] + __DATE__[4]) ^ __DATE__[5]) * (__TIME__[0] ^ (__TIME__[1] - __TIME__[3]) ^ __TIME__[4]))     // DATE: Mmm dd yyyy  // TIME: hh:mm:ss

//---------------------------------------------------------------------------
UINT _fastcall SizeDriver32(bool Alt)
{
#ifdef HAVEBINDRV32 
 return Alt?BSizeBinDrv32B:BSizeBinDrv32A;     
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
UINT _fastcall SizeDriver64(bool Alt)
{
#ifdef HAVEBINDRV64 
 return Alt?BSizeBinDrv64B:BSizeBinDrv64A;
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
UINT _fastcall ReadDriver32(PBYTE DstBuf, UINT BufSize, bool Alt)
{
#ifdef HAVEBINDRV32  
 BYTE  XorKey  = (Alt)?(XKeyBinDrv32B):(XKeyBinDrv32A);
 UINT  DrvSize = SizeDriver32(Alt);  
 PBYTE DrvPtr  = (Alt)?((PBYTE)&BinDrv32B):((PBYTE)&BinDrv32A);
 if(BufSize > DrvSize)BufSize = DrvSize;
 for(int ctr=0,bleft=BufSize;bleft > 0;ctr++,bleft--)DstBuf[ctr] = DecryptByteWithCtr(DrvPtr[ctr],XorKey,bleft); 
 DBGMSG("Decrypted with %02X",XorKey);
 return BufSize;
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
UINT _fastcall ReadDriver64(PBYTE DstBuf, UINT BufSize, bool Alt)
{
#ifdef HAVEBINDRV64  
 BYTE  XorKey  = (Alt)?(XKeyBinDrv64B):(XKeyBinDrv64A);
 UINT  DrvSize = SizeDriver64(Alt); 
 PBYTE DrvPtr  = (Alt)?((PBYTE)&BinDrv64B):((PBYTE)&BinDrv64A);
 if(BufSize > DrvSize)BufSize = DrvSize;
 for(int ctr=0,bleft=BufSize;bleft > 0;ctr++,bleft--)DstBuf[ctr] = DecryptByteWithCtr(DrvPtr[ctr],XorKey,bleft); 
 DBGMSG("Decrypted with %02X",XorKey);
 return BufSize;
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
#ifdef _DEBUG
int _fastcall PackDataBlockToFile(PBYTE Data, UINT DataSize, BYTE Key, LPSTR ArrName, CArr<BYTE>* DstFile)
{
 NPAQ8::MSTRM SrcBuf;
 NPAQ8::MSTRM DstBuf;
 char KeyLine[128];
 SrcBuf.AssignFrom(Data, DataSize);
 int res = NPAQ8::strm_compress(1, SrcBuf, DstBuf);
 if(res < 0){LOGMSG("Failed to compress %s: %i",ArrName,res); return -1;}
 unsigned long Size = 0;
 void* Buffer = DstBuf.GetBuffer(&Size);
 if(!Buffer || !Size){LOGMSG("No compressed data for %s!",ArrName); return -2;}
 LOGMSG("Packed size is %u for %s",Size,ArrName);
 int llen = wsprintfA(KeyLine,"#define XKey%s  0x%02X\r\n",ArrName,Key);
 DstFile->Append((PBYTE)&KeyLine, llen);
 if(BinDataToCArray(*DstFile, (PBYTE)Buffer, Size, ArrName, Key, sizeof(DWORD)) <= 0){LOGMSG("Failed to create BinDrv %s!",ArrName); return -3;}
 return 0;
}
//---------------------------------------------------------------------------
int _fastcall GenerateBinDrv(void)
{
 wchar_t DstPath32[] = {_L(PROJECT_DIR) L"DrvBin32.cpp"};     
 wchar_t DstPath64[] = {_L(PROJECT_DIR) L"DrvBin64.cpp"};    

 CArr<BYTE> TmpArr;
 CArr<BYTE> DstFile32;
 CArr<BYTE> DstFile64;
 BYTE XorKey = BINKEY;
 TmpArr.FromFile("N:\\DriverX32A.sys");
 if(PackDataBlockToFile(TmpArr.c_data(), TmpArr.Size(), XorKey, "BinDrv32A", &DstFile32) < 0){LOGMSG("Failed to create BinDrv32A!"); return -1;}
 TmpArr.FromFile("N:\\DriverX32B.sys");
 if(PackDataBlockToFile(TmpArr.c_data(), TmpArr.Size(), XorKey, "BinDrv32B", &DstFile32) < 0){LOGMSG("Failed to create BinDrv32B!"); return -2;}
 DstFile32.ToFile(DstPath32);
 LOGMSG("Saved BinDrv32 %02X: %ls",XorKey,&DstPath32);

 XorKey = ~((XorKey << 4)|(XorKey >> 4));
 TmpArr.FromFile("N:\\DriverX64A.sys");
 if(PackDataBlockToFile(TmpArr.c_data(), TmpArr.Size(), XorKey, "BinDrv64A", &DstFile64) < 0){LOGMSG("Failed to create BinDrv64A!"); return -3;}
 TmpArr.FromFile("N:\\DriverX64B.sys");
 if(PackDataBlockToFile(TmpArr.c_data(), TmpArr.Size(), XorKey, "BinDrv64B", &DstFile64) < 0){LOGMSG("Failed to create BinDrv64B!"); return -4;}
 DstFile64.ToFile(DstPath64);
 LOGMSG("Saved BinDrv64 %02X: %ls",XorKey,&DstPath64);
 return 0;
}
//---------------------------------------------------------------------------
#endif
//---------------------------------------------------------------------------
int _fastcall SaveDriverToFile(PWSTR Name, bool IsX64, PWSTR FilePathOut, PWSTR NormPathOut, bool Alt)
{
 NPAQ8::MSTRM SrcBuf, DstBuf;
 if(IsX64)
  {
   SrcBuf.AssignFrom(NULL, SizeDriver64(Alt));
   unsigned long Size = 0;
   void* Buffer = SrcBuf.GetBuffer(&Size);
   if(!ReadDriver64((PBYTE)Buffer, Size, Alt)){DBGMSG("DrvBin64.cpp is not preperly generated!"); return -1;}
  }
   else
    {
     SrcBuf.AssignFrom(NULL, SizeDriver32(Alt));
     unsigned long Size = 0;
     void* Buffer = SrcBuf.GetBuffer(&Size);
     if(!ReadDriver32((PBYTE)Buffer, Size, Alt)){DBGMSG("DrvBin32.cpp is not preperly generated!"); return -2;}
    }
 int res = NPAQ8::strm_decompress(1, 0, SrcBuf, DstBuf);    // Fastest (Same size)
 if(res < 0){DBGMSG("Failed to decompress the driver: %s, %u",Name,(int)IsX64); return -3;}
 unsigned long Size = 0;
 void* Buffer = DstBuf.GetBuffer(&Size);
 if(!Buffer || !Size){DBGMSG("Decompressed driver is empty: %s, %u",Name,(int)IsX64); return -4;}
 DBGMSG("Decompressed driver %ls size: %u",Name,Size);

 HANDLE hFile = NULL;
 DWORD Result = 0;
 BOOL  WrRes  = 0;
 wchar_t DrvPath[MAX_PATH];
 if(!IsValidHandle(hFile) && GetSystemDirectoryW(DrvPath,countof(DrvPath)))  // Requires Wow64EnableWow64FsRedirection
  {   
   lstrcatW(DrvPath, L"\\drivers\\");
   lstrcatW(DrvPath, Name);
   lstrcatW(DrvPath, L".sys");
   Wow64EnableWow64FsRedirection(FALSE);  // Required to try to save the driver in 'system32\drivers\' directory
   if(NormPathOut)lstrcpyW(NormPathOut, DrvPath);
   hFile = CreateFileW(DrvPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
   Wow64EnableWow64FsRedirection(TRUE);  
   if(hFile != INVALID_HANDLE_VALUE)        // WriteFile may fail with ERROR_INVALID_FUNCTION because some Antivirus seenng a created driver in 'drivers' directory steals its handle and remofes its file
    {    
     lstrcpyW(DrvPath, L"\\SystemRoot\\System32\\drivers\\");    // To look normal in registry
     lstrcatW(DrvPath, Name);
     lstrcatW(DrvPath, L".sys");
     WrRes = WriteFile(hFile,Buffer,Size,&Result,NULL);
     CloseHandle(hFile); 
     if(!WrRes || (Result != Size)){DBGMSG("Failed to write the driver file(%u): %ls",GetLastError(),&DrvPath); DeleteFileW(DrvPath);}
    }
     else 
      {
       UINT LstErr = GetLastError(); 
       DBGMSG("Failed to create the driver(%u) at: %ls",LstErr,&DrvPath);
       if(LstErr == ERROR_SHARING_VIOLATION){DBGMSG("Trying to reuse an already loaded driver!"); lstrcpyW(FilePathOut, DrvPath); return 0;}
      }
  }  
 if((!WrRes || (Result != Size)) && GetTempPathW(countof(DrvPath),DrvPath))
  {
   lstrcatW(DrvPath, Name);
   lstrcatW(DrvPath, L".dll");
   if(NormPathOut)lstrcpyW(NormPathOut, DrvPath);
   hFile = CreateFileW(DrvPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
   if(hFile == INVALID_HANDLE_VALUE)
    {
     UINT LstErr = GetLastError(); 
     DBGMSG("Failed to create the driver(%u) at: %ls",LstErr,&DrvPath); 
     if(LstErr == ERROR_SHARING_VIOLATION){DBGMSG("Trying to reuse an already loaded driver!"); lstrcpyW(FilePathOut, DrvPath); return 0;}
     return -5;
    }
   WrRes = WriteFile(hFile,Buffer,Size,&Result,NULL);   
   CloseHandle(hFile); 
  }
 if(!WrRes || (Result != Size)){DBGMSG("Failed to write the driver file(%u): %ls",GetLastError(),&DrvPath); DeleteFileW(DrvPath); return -6;} 
 DBGMSG("Driver %u saved to: %ls",(int)Alt,&DrvPath); 
 lstrcpyW(FilePathOut, DrvPath);
 return 0;
}
//---------------------------------------------------------------------------
