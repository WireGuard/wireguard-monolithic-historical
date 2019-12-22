// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdbool.h>

static HANDLE open_wireguard_pipe(const char *name)
{
	char fname[0x1000];
	HANDLE thread_token, process_snapshot, winlogon_process, winlogon_token, duplicated_token, pipe_handle;
	PROCESSENTRY32 entry = { .dwSize = sizeof(PROCESSENTRY32) };
	BOOL ret;
	DWORD pid = 0, last_error;
	TOKEN_PRIVILEGES privileges = {
		.PrivilegeCount = 1,
		.Privileges = {{ .Attributes = SE_PRIVILEGE_ENABLED }}
	};

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privileges.Privileges[0].Luid)) {
		fprintf(stderr, "Error: LookupPrivilegeValue: 0x%lx\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}
	if (!ImpersonateSelf(SecurityImpersonation)) {
		fprintf(stderr, "Error: ImpersonateSelf: 0x%lx\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &thread_token)) {
		fprintf(stderr, "Error: OpenThreadToken: 0x%lx\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}
	if (!AdjustTokenPrivileges(thread_token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
		fprintf(stderr, "Error: AdjustTokenPrivileges: 0x%lx\n", GetLastError());
		CloseHandle(thread_token);
		return INVALID_HANDLE_VALUE;
	}
	CloseHandle(thread_token);

	process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (process_snapshot == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Error: CreateToolhelp32Snapshot: 0x%lx\n", GetLastError());
		RevertToSelf();
		return INVALID_HANDLE_VALUE;
	}
	for (ret = Process32First(process_snapshot, &entry); ret; ret = Process32Next(process_snapshot, &entry)) {
		if (!strcasecmp(entry.szExeFile, "winlogon.exe")) {
			pid = entry.th32ProcessID;
			break;
		}
	}
	CloseHandle(process_snapshot);
	if (!pid) {
		fprintf(stderr, "Error: unable to find winlogon.exe\n");
		RevertToSelf();
		return INVALID_HANDLE_VALUE;
	}

	winlogon_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (!winlogon_process) {
		fprintf(stderr, "Error: OpenProcess: 0x%lx\n", GetLastError());
		RevertToSelf();
		return INVALID_HANDLE_VALUE;
	}

	if (!OpenProcessToken(winlogon_process, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &winlogon_token)) {
		fprintf(stderr, "Error: OpenProcessToken: 0x%lx\n", GetLastError());
		CloseHandle(winlogon_process);
		RevertToSelf();
		return INVALID_HANDLE_VALUE;
	}
	CloseHandle(winlogon_process);

	if (!DuplicateToken(winlogon_token, SecurityImpersonation, &duplicated_token)) {
		fprintf(stderr, "Error: DuplicateToken: 0x%lx\n", GetLastError());
		CloseHandle(winlogon_token);
		RevertToSelf();
		return INVALID_HANDLE_VALUE;
	}
	CloseHandle(winlogon_token);

	if (!SetThreadToken(NULL, duplicated_token)) {
		fprintf(stderr, "Error: SetThreadToken: 0x%lx\n", GetLastError());
		CloseHandle(duplicated_token);
		RevertToSelf();
		return INVALID_HANDLE_VALUE;
	}
	CloseHandle(duplicated_token);

	snprintf(fname, sizeof(fname), "\\\\.\\pipe\\WireGuard\\%s", name);
	pipe_handle = CreateFile(fname, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	last_error = GetLastError();
	RevertToSelf();
	if (pipe_handle == INVALID_HANDLE_VALUE)
		fprintf(stderr, "Error: CreateFile: 0x%lx\n", last_error);
	return pipe_handle;
}

int main(int argc, char *argv[])
{
	WIN32_FIND_DATA find_data;
	HANDLE find_handle, pipe_handle;
	char tunnel_info[0x10000];
	DWORD written;

	find_handle = FindFirstFile("\\\\.\\pipe\\*", &find_data);
	if (find_handle == INVALID_HANDLE_VALUE)
		fprintf(stderr, "Error: FindFirstFile: 0x%lx\n", GetLastError());
	do {
		if (!strncmp("WireGuard\\", find_data.cFileName, 10)) {
			printf("name=%s\n", find_data.cFileName + 10);
			pipe_handle = open_wireguard_pipe(find_data.cFileName + 10);
			if (pipe_handle == INVALID_HANDLE_VALUE)
				continue;
			if (!WriteFile(pipe_handle, "get=1\n\n", 7, &written, NULL))
				continue;
			if (!ReadFile(pipe_handle, tunnel_info, sizeof(tunnel_info) - 1, &written, NULL))
				continue;
			CloseHandle(pipe_handle);
			tunnel_info[written] = '\0';
			fputs(tunnel_info, stdout);
		}
	} while (FindNextFile(find_handle, &find_data));

	return 0;
}
