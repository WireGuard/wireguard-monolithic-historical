// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>

static FILE *userspace_interface_file(const char *interface)
{
	char fname[MAX_PATH], error_message[1024 * 128] = { 0 };
	HANDLE thread_token, process_snapshot, winlogon_process, winlogon_token, duplicated_token, pipe_handle = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 entry = { .dwSize = sizeof(PROCESSENTRY32) };
	BOOL ret;
	int fd;
	DWORD last_error = ERROR_SUCCESS;
	TOKEN_PRIVILEGES privileges = {
		.PrivilegeCount = 1,
		.Privileges = {{ .Attributes = SE_PRIVILEGE_ENABLED }}
	};

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
		goto err;

	process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (process_snapshot == INVALID_HANDLE_VALUE)
		goto err;
	for (ret = Process32First(process_snapshot, &entry); ret; last_error = GetLastError(), ret = Process32Next(process_snapshot, &entry)) {
		if (strcasecmp(entry.szExeFile, "winlogon.exe"))
			continue;

		RevertToSelf();
		if (!ImpersonateSelf(SecurityImpersonation))
			continue;
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &thread_token))
			continue;
		if (!AdjustTokenPrivileges(thread_token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
			last_error = GetLastError();
			CloseHandle(thread_token);
			continue;
		}
		CloseHandle(thread_token);

		winlogon_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
		if (!winlogon_process)
			continue;
		if (!OpenProcessToken(winlogon_process, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &winlogon_token))
			continue;
		CloseHandle(winlogon_process);
		if (!DuplicateToken(winlogon_token, SecurityImpersonation, &duplicated_token)) {
			last_error = GetLastError();
			RevertToSelf();
			continue;
		}
		CloseHandle(winlogon_token);
		if (!SetThreadToken(NULL, duplicated_token)) {
			last_error = GetLastError();
			CloseHandle(duplicated_token);
			continue;
		}
		CloseHandle(duplicated_token);

		snprintf(fname, sizeof(fname), "\\\\.\\pipe\\WireGuard\\%s", interface);
		pipe_handle = CreateFile(fname, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		last_error = GetLastError();
		if (pipe_handle != INVALID_HANDLE_VALUE) {
			last_error = ERROR_SUCCESS;
			break;
		}
	}
	RevertToSelf();
	CloseHandle(process_snapshot);

	if (last_error != ERROR_SUCCESS || pipe_handle == INVALID_HANDLE_VALUE)
		goto err;
	fd = _open_osfhandle((intptr_t)pipe_handle, _O_RDWR);
	if (fd == -1) {
		last_error = GetLastError();
		CloseHandle(pipe_handle);
		goto err;
	}
	return _fdopen(fd, "r+");

err:
	if (last_error == ERROR_SUCCESS)
		last_error = GetLastError();
	if (last_error == ERROR_SUCCESS)
		last_error = ERROR_ACCESS_DENIED;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, last_error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), error_message, sizeof(error_message) - 1, NULL);
	fprintf(stderr, "Error: Unable to open IPC handle via SYSTEM impersonation: %ld: %s\n", last_error, error_message);
	errno = EACCES;
	return NULL;
}

static int userspace_get_wireguard_interfaces(struct inflatable_buffer *buffer)
{
	WIN32_FIND_DATA find_data;
	HANDLE find_handle;
	int ret = 0;

	find_handle = FindFirstFile("\\\\.\\pipe\\*", &find_data);
	if (find_handle == INVALID_HANDLE_VALUE)
		return -GetLastError();
	do {
		if (strncmp("WireGuard\\", find_data.cFileName, 10))
			continue;
		buffer->next = strdup(find_data.cFileName + 10);
		buffer->good = true;
		ret = add_next_to_inflatable_buffer(buffer);
		if (ret < 0)
			goto out;
	} while (FindNextFile(find_handle, &find_data));

out:
	FindClose(find_handle);
	return ret;
}
