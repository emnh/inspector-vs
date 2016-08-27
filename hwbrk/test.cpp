// test

#include <windows.h>
#include "hwbrk.h"
#include <stdio.h>


const char* cH1 = "Breakpoint 1 hit!";
const char* cH2 = "Breakpoint 2 hit!";
const char* cH3 = "Breakpoint 3 hit!";
const char* cH4 = "Breakpoint 4 hit!";


void SomeFunc()
	{
	Sleep(10);
	Sleep(50);
	}

int __stdcall WinMain(HINSTANCE,HINSTANCE,LPSTR,int)
	{
	char c1[100] = {0};
	char c2[100] = {0};
	lstrcpyA(c1,"Hello 1");
	lstrcpyA(c2,"Hello 2");
	HANDLE hX1 = 0,hX2 = 0,hX3 = 0,hX4 = 0;

	hX1 = SetHardwareBreakpoint(GetCurrentThread(),HWBRK_TYPE_READWRITE,HWBRK_SIZE_4,c1);
	hX2 = SetHardwareBreakpoint(GetCurrentThread(),HWBRK_TYPE_WRITE,HWBRK_SIZE_1,c2);
	hX3 = SetHardwareBreakpoint(GetCurrentThread(),HWBRK_TYPE_CODE,HWBRK_SIZE_1,SomeFunc);
	hX4 = SetHardwareBreakpoint(GetCurrentThread(),HWBRK_TYPE_WRITE,HWBRK_SIZE_8,c2);

	__try
		{
		volatile char a1 = c1[2];
		}
	__except(GetExceptionCode() == STATUS_SINGLE_STEP)
		{
		MessageBoxA(0,cH1,0,MB_OK);
		}

	__try
		{
		c2[0] = 'Z';
		}
	__except(GetExceptionCode() == STATUS_SINGLE_STEP)
		{
		MessageBoxA(0,cH2,0,MB_OK);
		}

	__try
		{
		SomeFunc();
		}
	__except(GetExceptionCode() == STATUS_SINGLE_STEP)
		{
		MessageBoxA(0,cH3,0,MB_OK);
		}


	__try
		{
		c2[2] = 'Z';
		}
	__except(GetExceptionCode() == STATUS_SINGLE_STEP)
		{
		MessageBoxA(0,cH4,0,MB_OK);
		}


	RemoveHardwareBreakpoint(hX4);
	RemoveHardwareBreakpoint(hX3);
	RemoveHardwareBreakpoint(hX2);
	RemoveHardwareBreakpoint(hX1);
	}