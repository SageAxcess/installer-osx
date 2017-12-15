#include "stdafx.h"
#include <atlutil.h>
#include "CheckEdgeVersion.h"



enum {
	BOOL_TYPE = 1,
	STRING_TYPE,
	BOOL_STRING_TYPE,
	BOOL_STRING2_TYPE
};

typedef struct _command {
	int nType;
	CString strName;
	BOOL bVal;
	CString strVal[2];
}command;


command cmd[] = {
	{ STRING_TYPE, L"/minver", FALSE },
	
	{}
};

CAtlMap<CString, command*> cmdMap;


int ParceArgs() {
	for (command* c = cmd; c->strName != L""; ++c) {
		cmdMap.SetAt(c->strName, c);
	}

	for (int i = 0; i < __argc; i++) {
		TCHAR* pArg = __targv[i];
		command *c;
		if (cmdMap.Lookup(pArg, c)) {
			if (c->nType == BOOL_TYPE) {
				c->bVal = TRUE;
			}
			else if (c->nType == STRING_TYPE) {
				c->strVal[0] = __targv[++i];
			}
			else if (c->nType == BOOL_STRING_TYPE) {
				c->bVal = TRUE;
				c->strVal[0] = __targv[++i];
			}
			else if (c->nType == BOOL_STRING2_TYPE) {
				c->bVal = TRUE;
				c->strVal[0] = __targv[++i];
				c->strVal[1] = __targv[++i];
			}
		}
	}
	return __argc;
}



CString ExecAndGetOutput(CString strExePath, CString strParams) {

	// Allocate 1Mo to store the output (final buffer will be sized to actual output)
	// If output exceeds that size, it will be truncated
	const SIZE_T RESULT_SIZE = sizeof(char) * 1024 * 1024;
	CString strOut;


	HANDLE readPipe, writePipe;
	SECURITY_ATTRIBUTES security;
	STARTUPINFO        start;
	PROCESS_INFORMATION processInfo;

	security.nLength = sizeof(SECURITY_ATTRIBUTES);
	security.bInheritHandle = true;
	security.lpSecurityDescriptor = NULL;

	if (CreatePipe(
		&readPipe,  // address of variable for read handle
		&writePipe, // address of variable for write handle
		&security,  // pointer to security attributes
		0           // number of bytes reserved for pipe
	)) {


		GetStartupInfo(&start);
		start.hStdOutput = writePipe;
		start.hStdError = writePipe;
		start.hStdInput = readPipe;
		start.dwFlags = STARTF_USESTDHANDLES + STARTF_USESHOWWINDOW;
		start.wShowWindow = SW_HIDE;

		// We have to start the DOS app the same way cmd.exe does (using the current Win32 ANSI code-page).
		// So, we use the "ANSI" version of createProcess, to be able to pass a LPSTR (single/multi-byte character string) 
		// instead of a LPWSTR (wide-character string) and we use the UNICODEtoANSI function to convert the given command 
		if (CreateProcess(strExePath,                    // pointer to name of executable module
			strParams.GetBuffer(),  // pointer to command line string
			&security,               // pointer to process security attributes
			&security,               // pointer to thread security attributes
			TRUE,                    // handle inheritance flag
			NORMAL_PRIORITY_CLASS,   // creation flags
			NULL,                    // pointer to new environment block
			NULL,      // pointer to current directory name
			&start,                  // pointer to STARTUPINFO
			&processInfo             // pointer to PROCESS_INFORMATION
		)) {

			// wait for the child process to start
			for (UINT state = WAIT_TIMEOUT; state == WAIT_TIMEOUT; state = WaitForSingleObject(processInfo.hProcess, 100));

			DWORD bytesRead = 0, count = 0;
			const int BUFF_SIZE = 1024;
			char* buffer = (char*)malloc(sizeof(char)*BUFF_SIZE + 1);

			do {
				DWORD dwAvail = 0;
				if (!PeekNamedPipe(readPipe, NULL, 0, NULL, &dwAvail, NULL)) {
					// error, the child process might have ended
					break;
				}
				if (!dwAvail) {
					// no data available in the pipe
					break;
				}
				ReadFile(readPipe, buffer, BUFF_SIZE, &bytesRead, NULL);
				buffer[bytesRead] = '\0';
				if ((count + bytesRead) > RESULT_SIZE) break;
				strOut += buffer;
				count += bytesRead;

			} while (bytesRead >= BUFF_SIZE);
			free(buffer);
		}

	}

	CloseHandle(processInfo.hThread);
	CloseHandle(processInfo.hProcess);
	CloseHandle(writePipe);
	CloseHandle(readPipe);

	// convert result buffer to a wide-character string
	return strOut;
}




int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR  lpCmdLine, int nCmdShow) {
	
	ParceArgs();

	CString strMinVer;
	if (cmdMap[L"/minver"]->strVal[0] == L"") {
		return 2;
	}

	strMinVer = cmdMap[L"/minver"]->strVal[0];

	CString str =  ExecAndGetOutput(L"C:\\Windows\\system32\\cmd.exe", L"/C powershell -command \"& {&'get-appxpackage' '*edge*'}\"");
	int nPos = str.Find(L"Version", 0);
	if (nPos != -1) {
		int nEnd = str.Find(L"\r\n", nPos);
		str = str.Mid(nPos, nEnd - nPos);
		if ((nPos = str.Find(L":", 0)) != -1) {
			str = str.Mid(++nPos, str.GetLength());
			str = str.Trim();
			if (str < strMinVer) {
				return 1;
			}
		}
	}

	return 0;
}
