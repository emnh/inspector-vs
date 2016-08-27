// ContextLib.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "ContextLib.h"

// This is an example of an exported variable
CONTEXTLIB_API int nContextLib=0;

// This is an example of an exported function.
CONTEXTLIB_API int fnContextLib(void)
{
    return 42;
}

// This is the constructor of a class that has been exported.
// see ContextLib.h for the class definition
CContextLib::CContextLib()
{
    return;
}

#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <strsafe.h>

#define ACTION_SUSPEND 1
#define ACTION_RESUME 2
#define ACTION_GETCONTEXT 4

//#define ADD(instr) \
//	addInstruction(&ptr, UCHAR[]instr, sizeof(instr))

#define PRINT_SIZE(struct_) \
	printf("sizeof c " #struct_ ": %zu\n", sizeof(struct_));

void ErrorExit(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	//ExitProcess(dw);
}

extern "C" {

	__declspec(dllexport) DWORD64 getRip(unsigned int threadId, CONTEXT* context, int actions) {
		//printf("thread id: %d\n", threadId);

		// open a handle to the thread
		HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
			THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, threadId);

		if (hThread == NULL) {
			printf("Error opening thread handle.. 0x%08x\n", GetLastError());
			return 0;
		}

		// suspend the thread
		if (actions & ACTION_SUSPEND) {
			if (SuspendThread(hThread) == -1) {
				printf("Error suspending thread.. 0x%08x\n", GetLastError());
				CloseHandle(hThread);
				return 0;
			}
		}

		// get the thread context
		CONTEXT orig_ctx = { 0 };
		if (actions & ACTION_GETCONTEXT) {
			orig_ctx.ContextFlags = CONTEXT_FULL;
			if (GetThreadContext(hThread, &orig_ctx) == FALSE) {
				printf("Error  0x%08x\n", GetLastError());
				//ErrorExit(TEXT("GetThreadContext"));
				printf("Error in GetThreadContext\n");
				CloseHandle(hThread);
				return 0;
			}
		}

		// resume the thread
		if (actions & ACTION_RESUME) {
			if (ResumeThread(hThread) == -1) {
				printf("Error resuming thread.. 0x%08x\n", GetLastError());
				CloseHandle(hThread);
				return 0;
			}
		}

		CloseHandle(hThread);

		memcpy(context, &orig_ctx, sizeof orig_ctx);

		return orig_ctx.Rip;
	}

	__declspec(dllexport) DWORD64 setRip(unsigned int threadId, int suspend, DWORD64 Rip) {
		//printf("thread id: %d\n", threadId);

		// open a handle to the thread
		HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
			THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, threadId);

		if (hThread == NULL) {
			printf("Error opening thread handle.. 0x%08x\n", GetLastError());
			return 0;
		}

		// suspend the thread
		if (suspend) {
			if (SuspendThread(hThread) == -1) {
				printf("Error suspending thread.. 0x%08x\n", GetLastError());
				CloseHandle(hThread);
				return 0;
			}
		}

		// get the thread context
		CONTEXT orig_ctx = { 0 };
		orig_ctx.ContextFlags = CONTEXT_FULL;
		if (GetThreadContext(hThread, &orig_ctx) == FALSE) {
			printf("Error2  0x%08x\n", GetLastError());
			CloseHandle(hThread);
			return 0;
		}

		//orig_ctx.Dr0 = address;
		//CONTEXT new_ctx = { 0 };
		CONTEXT new_ctx = orig_ctx;
		//new_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; // | CONTEXT_INTEGER;
		new_ctx.ContextFlags = CONTEXT_FULL;
		//new_ctx.Dr0 = address;
		//new_ctx.Dr7 = 0x00000001;
		//printf("setting breakpoint: 0x%llx\n", new_ctx.Dr0);

		new_ctx.Rip = Rip;

		// Set the changed orig_ctx back
		if (SetThreadContext(hThread, &new_ctx) == FALSE) {
			printf("Error  0x%08x\n", GetLastError());
			CloseHandle(hThread);
			return 0;
		}

		// resume the thread
		if (suspend) {
			if (ResumeThread(hThread) == -1) {
				printf("Error resuming thread.. 0x%08x\n", GetLastError());
				CloseHandle(hThread);
				return 0;
			}
		}

		CloseHandle(hThread);

		return orig_ctx.Rip;
	}

	__declspec(dllexport) DWORD64 setTrace(unsigned int threadId, int suspend, int clear) {
		//printf("thread id: %d\n", threadId);

		// open a handle to the thread
		HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
			THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, threadId);

		if (hThread == NULL) {
			printf("Error opening thread handle.. 0x%08x\n", GetLastError());
			return 0;
		}

		// suspend the thread
		if (suspend) {
			if (SuspendThread(hThread) == -1) {
				printf("Error suspending thread.. 0x%08x\n", GetLastError());
				CloseHandle(hThread);
				return 0;
			}
		}

		// get the thread context
		CONTEXT orig_ctx = { 0 };
		orig_ctx.ContextFlags = CONTEXT_FULL;
		if (GetThreadContext(hThread, &orig_ctx) == FALSE) {
			printf("Error2  0x%08x\n", GetLastError());
			CloseHandle(hThread);
			return 0;
		}

		//orig_ctx.Dr0 = address;
		//CONTEXT new_ctx = { 0 };
		CONTEXT new_ctx = orig_ctx;
		//new_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; // | CONTEXT_INTEGER;
		new_ctx.ContextFlags = CONTEXT_FULL;
		//new_ctx.Dr0 = address;
		//new_ctx.Dr7 = 0x00000001;
		//printf("setting breakpoint: 0x%llx\n", new_ctx.Dr0);
		
		if (clear) {
			DWORD64 bit = 0x0100;
			new_ctx.EFlags &= ~bit;
		}
		else {
			new_ctx.EFlags |= 0x0100;
		}

		// Set the changed orig_ctx back
		if (SetThreadContext(hThread, &new_ctx) == FALSE) {
			printf("Error  0x%08x\n", GetLastError());
			CloseHandle(hThread);
			return 0;
		}

		// resume the thread
		if (suspend) {
			if (ResumeThread(hThread) == -1) {
				printf("Error resuming thread.. 0x%08x\n", GetLastError());
				CloseHandle(hThread);
				return 0;
			}
		}

		CloseHandle(hThread);

		return orig_ctx.Rip;
	}

	__declspec(dllexport) DWORD64 setHardwareBreakPoint(unsigned int threadId, DWORD64 address, int suspend, int clear) {
		//printf("thread id: %d\n", threadId);

		// open a handle to the thread
		HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
			THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, threadId);

		if (hThread == NULL) {
			printf("Error opening thread handle.. 0x%08x\n", GetLastError());
			return 0;
		}

		// suspend the thread
		if (suspend) {
			if (SuspendThread(hThread) == -1) {
				printf("Error suspending thread.. 0x%08x\n", GetLastError());
				CloseHandle(hThread);
				return 0;
			}
		}

		// get the thread context
		CONTEXT orig_ctx = { 0 };
		orig_ctx.ContextFlags = CONTEXT_FULL;
		if (GetThreadContext(hThread, &orig_ctx) == FALSE) {
			printf("Error2  0x%08x\n", GetLastError());
			CloseHandle(hThread);
			return 0;
		}

		//orig_ctx.Dr0 = address;
		//CONTEXT new_ctx = { 0 };
		CONTEXT new_ctx = orig_ctx;
		//new_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; // | CONTEXT_INTEGER;
		new_ctx.ContextFlags = CONTEXT_FULL;
		if (clear) {
			printf("clearing breakpoint: 0x%llx,0x%llx\n", address, new_ctx.Dr0);
			new_ctx.Dr0 = 0;
			new_ctx.Dr7 = 0;
		} else {
			new_ctx.Dr0 = address;
			new_ctx.Dr1 = address;
			new_ctx.Dr2 = address;
			new_ctx.Dr3 = address;
			new_ctx.Dr7 = 0x00000001 | 0x00000001 << 2 | 0x00000001 << 4 | 0x00000001 << 6;
			printf("setting breakpoint: 0x%llx\n", new_ctx.Dr0);
		}

		// Set the changed orig_ctx back
		if (SetThreadContext(hThread, &new_ctx) == FALSE) {
			printf("Error  0x%08x\n", GetLastError());
			CloseHandle(hThread);
			return 0;
		}

		// resume the thread
		if (suspend) {
			if (ResumeThread(hThread) == -1) {
				printf("Error resuming thread.. 0x%08x\n", GetLastError());
				CloseHandle(hThread);
				return 0;
			}
		}

		CloseHandle(hThread);

		return orig_ctx.Rip;
	}
	
	/*
	DWORD OnCreateThreadDebugEvent(const LPDEBUG_EVENT);
	DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT);
	DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT);
	DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT);
	DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT);
	DWORD OnUnloadDllDebugEvent(const LPDEBUG_EVENT);
	DWORD OnOutputDebugStringEvent(const LPDEBUG_EVENT);
	DWORD OnRipEvent(const LPDEBUG_EVENT);
	*/

	__declspec(dllexport) BOOL handleDebugEvent(LPDEBUG_EVENT event, DWORD* continueStatus)
	{
		DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation
		
		const LPDEBUG_EVENT DebugEv = { 0 };

		// Wait for a debugging event to occur.
		BOOL retVal = WaitForDebugEvent(DebugEv, 0);

		//event = DebugEv;
		memcpy(event, DebugEv, sizeof(LPDEBUG_EVENT));

		// Process the debugging event code.
		switch (DebugEv->dwDebugEventCode) {
			case EXCEPTION_DEBUG_EVENT:
				// Process the exception code. When handling 
				// exceptions, remember to set the continuation 
				// status parameter (dwContinueStatus). This value 
				// is used by the ContinueDebugEvent function. 
				switch (DebugEv->u.Exception.ExceptionRecord.ExceptionCode) {
					case EXCEPTION_ACCESS_VIOLATION:
						// First chance: Pass this on to the system. 
						// Last chance: Display an appropriate error.
						printf("EXCEPTION_DEBUG_EVENT.EXCEPTION_ACCESS_VIOLATION\n");
						break;

					case EXCEPTION_BREAKPOINT:
						// First chance: Display the current 
						// instruction and register values. 
						printf("EXCEPTION_DEBUG_EVENT.EXCEPTION_BREAKPOINT\n");
						break;

					case EXCEPTION_DATATYPE_MISALIGNMENT:
						// First chance: Pass this on to the system. 
						// Last chance: Display an appropriate error. 
						printf("EXCEPTION_DEBUG_EVENT.EXCEPTION_DATATYPE_MISALIGNMENT\n");
						break;

					case EXCEPTION_SINGLE_STEP:
						// First chance: Update the display of the 
						// current instruction and register values.
						printf("EXCEPTION_DEBUG_EVENT.EXCEPTION_SINGLE_STEP\n");
						break;

					case DBG_CONTROL_C:
						// First chance: Pass this on to the system. 
						// Last chance: Display an appropriate error.
						printf("EXCEPTION_DEBUG_EVENT.DBG_CONTROL_C\n");
						break;

					default:
						printf("EXCEPTION_DEBUG_EVENT.DEFAULT\n");
						// Handle other exceptions. 
						break;
				}

				break;

			case CREATE_THREAD_DEBUG_EVENT:
				// As needed, examine or change the thread's registers 
				// with the GetThreadContext and SetThreadContext functions; 
				// and suspend and resume thread execution with the 
				// SuspendThread and ResumeThread functions. 

				//dwContinueStatus = OnCreateThreadDebugEvent(DebugEv);
				printf("CREATE_THREAD_DEBUG_EVENT\n");
				break;

			case CREATE_PROCESS_DEBUG_EVENT:
				// As needed, examine or change the registers of the
				// process's initial thread with the GetThreadContext and
				// SetThreadContext functions; read from and write to the
				// process's virtual memory with the ReadProcessMemory and
				// WriteProcessMemory functions; and suspend and resume
				// thread execution with the SuspendThread and ResumeThread
				// functions. Be sure to close the handle to the process image
				// file with CloseHandle.

				printf("CREATE_PROCESS_DEBUG_EVENT\n");
				break;

			case EXIT_THREAD_DEBUG_EVENT:
				// Display the thread's exit code. 

				//dwContinueStatus = OnExitThreadDebugEvent(DebugEv);
				printf("EXIT_THREAD_DEBUG_EVENT\n");
				break;

			case EXIT_PROCESS_DEBUG_EVENT:
				// Display the process's exit code. 

				//dwContinueStatus = OnExitProcessDebugEvent(DebugEv);
				printf("EXIT_PROCESS_DEBUG_EVENT\n");
				break;

			case LOAD_DLL_DEBUG_EVENT:
				// Read the debugging information included in the newly 
				// loaded DLL. Be sure to close the handle to the loaded DLL 
				// with CloseHandle.

				//dwContinueStatus = OnLoadDllDebugEvent(DebugEv);
				printf("LOAD_DLL_DEBUG_EVENT\n");
				break;

			case UNLOAD_DLL_DEBUG_EVENT:
				// Display a message that the DLL has been unloaded. 

				//dwContinueStatus = OnUnloadDllDebugEvent(DebugEv);
				printf("UNLOAD_DLL_DEBUG_EVENT\n");
				break;

			case OUTPUT_DEBUG_STRING_EVENT:
				// Display the output debugging string. 

				//dwContinueStatus = OnOutputDebugStringEvent(DebugEv);
				printf("OUTPUT_DEBUG_STRING_EVENT\n");
				break;

			case RIP_EVENT:
				//dwContinueStatus = OnRipEvent(DebugEv);
				printf("RIP_EVENT\n");
				break;
		}


		// Resume executing the thread that reported the debugging event. 
		*continueStatus = dwContinueStatus;
		/*ContinueDebugEvent(DebugEv->dwProcessId,
			DebugEv->dwThreadId,
			dwContinueStatus);*/
		return retVal;
	}

	//
	//  SetPrivilege enables/disables process token privilege.
	//
	BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
	{
		LUID luid;
		BOOL bRet = FALSE;

		if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
		{
			TOKEN_PRIVILEGES tp;

			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;
			//
			//  Enable the privilege or disable all privileges.
			//
			if (AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
			{
				//
				//  Check to see if you have proper access.
				//  You may get "ERROR_NOT_ALL_ASSIGNED".
				//
				DWORD lastError = GetLastError();
				bRet = (lastError == ERROR_SUCCESS);
				if (lastError == ERROR_NOT_ALL_ASSIGNED) {
					printf("insufficient privilege\n");
				}
			}
		}
		return bRet;
	}

	__declspec(dllexport) void setDebugPrivilege() {
		HANDLE hProcess = GetCurrentProcess();
		HANDLE hToken;

		if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
			CloseHandle(hToken);
		}
	}

	struct TraceState {
		char* error;
		HANDLE codeAddress;
	};

	__declspec(dllexport) bool installTracer(int someProcessID, TraceState* traceState, PVOID patchSite) {
		HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, someProcessID);

		const int errorSize = 100;

		if (processHandle == NULL)
		{
			//some error
			traceState->error = (char*) calloc(errorSize, 1);
			sprintf_s(traceState->error, errorSize, "could not open process\n");
			return false;
		}
		
		const int patchSiteSize = 24;
		const int codeSize = 1024;
		UCHAR* originalCode = (UCHAR*) calloc(patchSiteSize, 1);

		BOOL readSucceed = ReadProcessMemory(processHandle,
			patchSite,
			originalCode,
			patchSiteSize,
			NULL);

		if (!readSucceed) {
			traceState->error = (char*) calloc(errorSize, 1);
			sprintf_s(traceState->error, errorSize, "could not read process memory\n");
			return false;
		}

		HANDLE codeAddress = VirtualAllocEx(
			processHandle,
			NULL,
			codeSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
		traceState->codeAddress = codeAddress;
		if (codeAddress == NULL) {
			traceState->error = (char*)calloc(errorSize, 1);
			sprintf_s(traceState->error, errorSize, "could not allocate memory\n");
			return false;
		}
		//printf("C code address: %llx\n", (DWORD64)codeAddress);

		UCHAR* patchSiteCode = (UCHAR*) calloc(patchSiteSize, 1);
		UCHAR* patchPtr = patchSiteCode;
		UCHAR* codeSiteCode = (UCHAR*) calloc(codeSize, 1);
		UCHAR* ptr = codeSiteCode;
		
		// push rax, see RESTORE_RAX
		*patchPtr++ = 0x50;
		// lea rax, [rip-8]
		*patchPtr++ = 0x48;
		*patchPtr++ = 0x8D;
		*patchPtr++ = 0x05;
		*patchPtr++ = 0xF8;
		*patchPtr++ = 0xFF;
		*patchPtr++ = 0xFF;
		*patchPtr++ = 0xFF;
		// push rax (rip)
		*patchPtr++ = 0x50;
		// mov rax, constant
		*patchPtr++ = 0x48;		
		*patchPtr++ = 0xB8;
		memcpy(patchPtr, &codeAddress, 8);
		patchPtr += 8;
		// push rax
		*patchPtr++ = 0x50;
		// ret
		*patchPtr++ = 0xC3;
		patchPtr += 3;
		
		if (patchPtr - patchSiteCode != patchSiteSize) {
			traceState->error = (char*)calloc(errorSize, 1);
			sprintf_s(traceState->error, errorSize, "made a mistake: %llu\n", patchPtr - patchSiteCode);
			return false;
		}

		// push rbp
		*ptr++ = 0x55;
		// mov rbp, rsp
		*ptr++ = 0x48;
		*ptr++ = 0x89;
		*ptr++ = 0xE5;
		// push rbx
		*ptr++ = 0x53;
		// push rax
		// *ptr++ = 0x50;

		// reserve space for last Rip address
		// mov rax, constant
		*ptr++ = 0x48;
		*ptr++ = 0xB8;
		const UCHAR* smcLastRip = ptr;
		ptr += 8;

		// lea rax, [rip-7-8]
		*ptr++ = 0x48;
		*ptr++ = 0x8D;
		*ptr++ = 0x05;
		*ptr++ = 0xF1;
		*ptr++ = 0xFF;
		*ptr++ = 0xFF;
		*ptr++ = 0xFF;

		// find return address
		// mov rbx, [rbp+8]
		*ptr++ = 0x48;
		*ptr++ = 0x8B;
		*ptr++ = 0x5D;
		*ptr++ = 0x08;

		// store return address
		// mov [rax], rbx
		*ptr++ = 0x48;
		*ptr++ = 0x89;
		*ptr++ = 0x18;

		// subtract call site from return address
		// sub rbx,constant
		/*
		*ptr++ = 0x48;
		*ptr++ = 0x83;
		*ptr++ = 0xEB;
		*ptr++ = (UCHAR) patchSiteSize;
		*/

		// put new return address back on stack
		// mov [rbp+8], rbx
		*ptr++ = 0x48;
		*ptr++ = 0x89;
		*ptr++ = 0x5D;
		*ptr++ = 0x08;

		// reserve space for call site restore 1
		// mov rax, constant
		*ptr++ = 0x48;
		*ptr++ = 0xB8;
		memcpy(ptr, originalCode, 8);
		ptr += 8;

		// restore call site 1
		// mov [ebx], rax
		*ptr++ = 0x48;
		*ptr++ = 0x89;
		*ptr++ = 0x03;

		// reserve space for call site restore 2
		// mov rax, constant
		*ptr++ = 0x48;
		*ptr++ = 0xB8;
		memcpy(ptr, originalCode + 8, 8);
		ptr += 8;

		// restore call site 2
		// mov [ebx+8], rax
		*ptr++ = 0x48;
		*ptr++ = 0x89;
		*ptr++ = 0x43;
		*ptr++ = 0x08;

		// reserve space for call site restore 3
		// mov rax, constant
		*ptr++ = 0x48;
		*ptr++ = 0xB8;
		memcpy(ptr, originalCode + 16, 8);
		ptr += 8;

		// restore call site 3
		// mov [ebx], rax
		*ptr++ = 0x48;
		*ptr++ = 0x89;
		*ptr++ = 0x43;
		*ptr++ = 0x10;

		// call rax
		//*ptr++ = 0xFF;
		//*ptr++ = 0xD0;
		
		// mov rax,[rbp+16]
		*ptr++ = 0x48;
		*ptr++ = 0x8B;
		*ptr++ = 0x45;
		*ptr++ = 0x10;

		// pop rax
		// *ptr++ = 0x58;
		// pop rbx
		*ptr++ = 0x5B;
		// pop rbp
		*ptr++ = 0x5D;
		// ret 8
		*ptr++ = 0xC2;
		*ptr++ = 0x08;
		*ptr++ = 0x00;

		BOOL isSucceeded = WriteProcessMemory(processHandle,
			codeAddress,
			codeSiteCode,
			codeSize,
			NULL);

		if (!isSucceeded) {
			traceState->error = (char*)calloc(errorSize, 1);
			sprintf_s(traceState->error, errorSize, "could not write process memory: allocated code\n");
			return false;
		}

		isSucceeded = WriteProcessMemory(processHandle,
			patchSite,
			patchSiteCode,
			patchSiteSize,
			NULL);

		if (!isSucceeded) {
			traceState->error = (char*)calloc(errorSize, 1);
			sprintf_s(traceState->error, errorSize, "could not write process memory: patch site\n");
			return false;
		}
		
		return true;
	}

	__declspec(dllexport) void testMain() {
		DEBUG_EVENT evt = { 0 };
		char* addr = (char*) &evt;
		printf("ptr c dwDebugEventCode: %llu\n", (char*) &(evt.dwDebugEventCode) - addr);
		printf("ptr c dwProcessId: %llu\n", (char*) &(evt.dwProcessId) - addr);
		printf("ptr c dwThreadId: %llu\n", (char*) &(evt.dwThreadId) - addr);
		printf("ptr c u: %llu\n", (char*) &(evt.u) - addr);

		printf("sizeof c DEBUG_EVENT: %zu\n", sizeof(DEBUG_EVENT));
		printf("sizeof c EXCEPTION_DEBUG_INFO: %zu\n", sizeof(EXCEPTION_DEBUG_INFO));
		printf("sizeof c EXCEPTION_RECORD: %zu\n", sizeof(EXCEPTION_RECORD));
		printf("sizeof c CREATE_THREAD_DEBUG_INFO: %zu\n", sizeof(CREATE_THREAD_DEBUG_INFO));
		printf("sizeof c CREATE_PROCESS_DEBUG_INFO: %zu\n", sizeof(CREATE_PROCESS_DEBUG_INFO));
		printf("sizeof c EXIT_THREAD_DEBUG_INFO: %zu\n", sizeof(EXIT_THREAD_DEBUG_INFO));
		printf("sizeof c EXIT_PROCESS_DEBUG_INFO: %zu\n", sizeof(EXIT_PROCESS_DEBUG_INFO));
		printf("sizeof c LOAD_DLL_DEBUG_INFO: %zu\n", sizeof(LOAD_DLL_DEBUG_INFO));
		printf("sizeof c UNLOAD_DLL_DEBUG_INFO: %zu\n", sizeof(UNLOAD_DLL_DEBUG_INFO));
		printf("sizeof c OUTPUT_DEBUG_STRING_INFO: %zu\n", sizeof(OUTPUT_DEBUG_STRING_INFO));
		printf("sizeof c RIP_INFO: %zu\n", sizeof(RIP_INFO));

		PRINT_SIZE(MEMORY_BASIC_INFORMATION);
		PRINT_SIZE(PVOID);
		PRINT_SIZE(DWORD);
		PRINT_SIZE(SIZE_T);

		PRINT_SIZE(SYSTEM_INFO);
	}

	int main() {
		//printf("size: %d\n", sizeof(LPCVOID));
		//printf("size: %x\n", EXCEPTION_BREAKPOINT);
	}

}