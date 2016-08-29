// DebugTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"

int main()
{
	DWORD64 s = 0;
	while (true) {
		for (int i = 0; i < 1e8; i++) {
			s += i;
		}
		
		printf("hello: %x %llx\n", GetCurrentThreadId(), s);
	}
    return 0;
}

