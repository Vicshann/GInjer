
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
#include "DrvBin32.cpp"
#endif

#if __has_include("DrvBin64.cpp")
#define HAVEBINDRV64 1
#include "DrvBin64.cpp"
#endif

#define BINKEY ((__DATE__[0] ^ (__DATE__[1] - __DATE__[2] + __DATE__[4]) ^ __DATE__[5]) * (__TIME__[0] ^ (__TIME__[1] - __TIME__[3]) ^ __TIME__[4]))     // DATE: Mmm dd yyyy  // TIME: hh:mm:ss

//---------------------------------------------------------------------------
UINT _fastcall SizeDriver32(void)
{
#ifdef HAVEBINDRV32 
 return BSizeBinDrv32;     
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
UINT _fastcall SizeDriver64(void)
{
#ifdef HAVEBINDRV64 
 return BSizeBinDrv64;
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
UINT _fastcall ReadDriver32(PBYTE DstBuf, UINT BufSize)
{
#ifdef HAVEBINDRV32     
 if(BufSize > BSizeBinDrv32)BufSize = BSizeBinDrv32;
 for(int ctr=0,bleft=BufSize;bleft > 0;ctr++,bleft--)DstBuf[ctr] = DecryptByteWithCtr(((PBYTE)&BinDrv32)[ctr],XKeyBinDrv32,bleft); 
 DBGMSG("Decrypted with %02X",XKeyBinDrv32);
 return BufSize;
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
UINT _fastcall ReadDriver64(PBYTE DstBuf, UINT BufSize)
{
#ifdef HAVEBINDRV64    
 if(BufSize > BSizeBinDrv64)BufSize = BSizeBinDrv64;
 for(int ctr=0,bleft=BufSize;bleft > 0;ctr++,bleft--)DstBuf[ctr] = DecryptByteWithCtr(((PBYTE)&BinDrv64)[ctr],XKeyBinDrv64,bleft); 
 DBGMSG("Decrypted with %02X",XKeyBinDrv64);
 return BufSize;
#else
 return 0;
#endif
}
//---------------------------------------------------------------------------
#ifdef _DEBUG
int _fastcall PackDataBlockToFile(PBYTE Data, UINT DataSize, BYTE Key, LPSTR ArrName, PWSTR FilePath)
{
 CArr<BYTE> DstFile;
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
 DstFile.Append((PBYTE)&KeyLine, llen);
 if(BinDataToCArray(DstFile, (PBYTE)Buffer, Size, ArrName, Key, sizeof(DWORD)) <= 0){LOGMSG("Failed to create BinDrv %s!",ArrName); return -3;}
 DstFile.ToFile(FilePath);
 LOGMSG("Saved BinDrv %02X: %ls",Key,FilePath);
 return 0;
}
//---------------------------------------------------------------------------
int _fastcall GenerateBinDrv(void)
{
 wchar_t DstPath32[] = {_L(PROJECT_DIR) L"DrvBin32.cpp"};     
 wchar_t DstPath64[] = {_L(PROJECT_DIR) L"DrvBin64.cpp"};    

 CArr<BYTE> TmpArr;
 BYTE XorKey = BINKEY;
 TmpArr.FromFile("N:\\DriverX32.sys");
 if(PackDataBlockToFile(TmpArr.c_data(), TmpArr.Size(), XorKey, "BinDrv32", DstPath32) < 0){LOGMSG("Failed to create BinDrv32!"); return -1;}

 XorKey = ~((XorKey << 4)|(XorKey >> 4));
 TmpArr.FromFile("N:\\DriverX64.sys");
 if(PackDataBlockToFile(TmpArr.c_data(), TmpArr.Size(), XorKey, "BinDrv64", DstPath64) < 0){LOGMSG("Failed to create BinDrv64!"); return -2;}
 LOGMSG("Done");
 return 0;
}
//---------------------------------------------------------------------------
#endif
//---------------------------------------------------------------------------
int _fastcall SaveDriverToFile(PWSTR Name, bool IsX64, PWSTR FilePathOut)
{
 NPAQ8::MSTRM SrcBuf, DstBuf;
 if(IsX64)
  {
   SrcBuf.AssignFrom(NULL, SizeDriver64());
   unsigned long Size = 0;
   void* Buffer = SrcBuf.GetBuffer(&Size);
   if(!ReadDriver64((PBYTE)Buffer, Size)){DBGMSG("DrvBin64.cpp is not preperly generated!"); return -1;}
  }
   else
    {
     SrcBuf.AssignFrom(NULL, SizeDriver32());
     unsigned long Size = 0;
     void* Buffer = SrcBuf.GetBuffer(&Size);
     if(!ReadDriver32((PBYTE)Buffer, Size)){DBGMSG("DrvBin32.cpp is not preperly generated!"); return -2;}
    }
 int res = NPAQ8::strm_decompress(1, 0, SrcBuf, DstBuf);    // Fastest (Same size)
 if(res < 0){DBGMSG("Failed to decompress the driver: %s, %u",Name,(int)IsX64); return -3;}
 unsigned long Size = 0;
 void* Buffer = DstBuf.GetBuffer(&Size);
 if(!Buffer || !Size){DBGMSG("Decompressed driver is empty: %s, %u",Name,(int)IsX64); return -4;}
 DBGMSG("Decompressed driver %ls size: %u",Name,Size);

 HANDLE hFile = NULL;
 wchar_t DrvPath[MAX_PATH];
 Wow64EnableWow64FsRedirection(FALSE);  // Required to try to save the driver in 'system32\drivers\' directory
 if(!IsValidHandle(hFile) && GetSystemDirectoryW(DrvPath,countof(DrvPath)))  // Requires Wow64EnableWow64FsRedirection
  {   
   lstrcatW(DrvPath, L"\\drivers\\");
   lstrcatW(DrvPath, Name);
   lstrcatW(DrvPath, L".sys");
   hFile = CreateFileW(DrvPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
   if(hFile != INVALID_HANDLE_VALUE)
    {
     lstrcpyW(DrvPath, L"\\SystemRoot\\System32\\drivers\\");    // To look normal in registry
     lstrcatW(DrvPath, Name);
     lstrcatW(DrvPath, L".sys");
    }
  }
 Wow64EnableWow64FsRedirection(TRUE);  
 if(!IsValidHandle(hFile) && GetTempPathW(countof(DrvPath),DrvPath))
  {
   lstrcatW(DrvPath, Name);
   lstrcatW(DrvPath, L".dll");
   hFile = CreateFileW(DrvPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
  }
 if(!IsValidHandle(hFile)){DBGMSG("Failed to create the driver file!"); return -5;}
 DWORD Result = 0;
 if(!WriteFile(hFile,Buffer,Size,&Result,NULL) || (Result != Size)){CloseHandle(hFile); DBGMSG("Failed to write the driver file: %ls",&DrvPath); return -6;} 
 DBGMSG("Driver saved to: %ls",&DrvPath);
 CloseHandle(hFile); 
 lstrcpyW(FilePathOut, DrvPath);
 return 0;
}
//---------------------------------------------------------------------------
