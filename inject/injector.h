#include "utils.h"
#include <conio.h>
#include <cstdlib>
#include <shellapi.h>
#include <string>
#include <curl.h>

#include "authgg/xor.h"
#include "authgg/lw_http.hpp"
#include "authgg/print.h"
#include "authgg/hwid.h"
#include "authgg/md5wrapper.h"
#include "authgg/crypto.h"
#include "authgg/authgg.h"

#include <CkCrypt2.h>
#include <CkBinData.h>
#include <CkByteData.h>

#pragma comment(lib, "ntdll")
#pragma comment(lib, "Ws2_32")
#pragma comment(lib, "Crypt32")
#pragma comment(lib, "ChilkatRelDll_x64")

#include <VMProtectSDK.h>
#pragma comment(lib, "VMProtectSDK64.lib")

#include "..\xor.h"
#include "..\lazy.h"
//#include "..\mem_drv_pub.h"
#include "..\mem_drv_priv.h"
#include "..\cheat.h"
extern "C" NTSTATUS NTAPI RtlCreateRegistryKey(ULONG RelativeTo, PWSTR Path);

using namespace std;
BYTE remote_load_library[96] = 
{
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20,
	0x83, 0x38, 0x00, 0x75, 0x3D, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40,
	0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x83, 0xC0, 0x18, 0x48, 0x8B, 0xC8, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B,
	0x4C, 0x24, 0x20, 0x48, 0x89, 0x41, 0x10, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
};

BYTE remote_call_dll_main[92] = 
{
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24,
	0x20, 0x83, 0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
	0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
	0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
}; DWORD shell_data_offset = 0x6;

typedef struct _load_library_struct
{
	int status;
	uintptr_t fn_load_library_a;
	uintptr_t module_base;
	char module_name[80];
}load_library_struct;

typedef struct _main_struct
{
	int status;
	uintptr_t fn_dll_main;
	HINSTANCE dll_base;
} main_struct;

uintptr_t call_remote_load_library(DWORD thread_id, LPCSTR dll_name)
{
	HMODULE nt_dll = LoadLibraryW(wxorstr_(L"ntdll.dll"));
	PVOID alloc_shell_code = driver().alloc_memory_ex(4096, PAGE_EXECUTE_READWRITE);
	DWORD shell_size = sizeof(remote_load_library) + sizeof(load_library_struct);
	PVOID alloc_local = VirtualAlloc(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	RtlCopyMemory(alloc_local, &remote_load_library, sizeof(remote_load_library));
	uintptr_t shell_data = (uintptr_t)alloc_shell_code + sizeof(remote_load_library);
	*(uintptr_t*)((uintptr_t)alloc_local + shell_data_offset) = shell_data;
	load_library_struct* ll_data = (load_library_struct*)((uintptr_t)alloc_local + sizeof(remote_load_library));
	ll_data->fn_load_library_a = (uintptr_t)LoadLibraryA;
	strcpy_s(ll_data->module_name, 80, dll_name);
	driver().write_memory_ex(alloc_shell_code, alloc_local, shell_size);
	HHOOK h_hook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)alloc_shell_code, nt_dll, thread_id);
	while (ll_data->status != 2) 
	{
		PostThreadMessage(thread_id, WM_NULL, 0, 0);
		driver().read_memory_ex((PVOID)shell_data, (PVOID)ll_data, sizeof(load_library_struct));
		Sleep(10);
	} uintptr_t mod_base = ll_data->module_base;
	UnhookWindowsHookEx(h_hook);
	driver().free_memory_ex(alloc_shell_code);
	VirtualFree(alloc_local, 0, MEM_RELEASE);

	return mod_base;
}

void call_dll_main(DWORD thread_id, PVOID dll_base, PIMAGE_NT_HEADERS nt_header, bool hide_dll)
{
	HMODULE nt_dll = LoadLibraryW(wxorstr_(L"ntdll.dll"));
	PVOID alloc_shell_code = driver().alloc_memory_ex(4096, PAGE_EXECUTE_READWRITE);
	DWORD shell_size = sizeof(remote_call_dll_main) + sizeof(main_struct);
	PVOID alloc_local = VirtualAlloc(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	RtlCopyMemory(alloc_local, &remote_call_dll_main, sizeof(remote_call_dll_main));
	uintptr_t shell_data = (uintptr_t)alloc_shell_code + sizeof(remote_call_dll_main);
	*(uintptr_t*)((uintptr_t)alloc_local + shell_data_offset) = shell_data;
	main_struct* main_data = (main_struct*)((uintptr_t)alloc_local + sizeof(remote_call_dll_main));
	main_data->dll_base = (HINSTANCE)dll_base;
	main_data->fn_dll_main = ((uintptr_t)dll_base + nt_header->OptionalHeader.AddressOfEntryPoint);
	driver().write_memory_ex(alloc_shell_code, alloc_local, shell_size);
	HHOOK h_hook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)alloc_shell_code, nt_dll, thread_id);
	while (main_data->status != 2)
	{
		PostThreadMessage(thread_id, WM_NULL, 0, 0);
		driver().read_memory_ex((PVOID)shell_data, (PVOID)main_data, sizeof(main_struct));
		Sleep(10);
	}
	UnhookWindowsHookEx(h_hook);
	driver().free_memory_ex(alloc_shell_code);
	VirtualFree(alloc_local, 0, MEM_RELEASE);
}

PVOID rva_va(uintptr_t rva, PIMAGE_NT_HEADERS nt_head, PVOID local_image)
{
	PIMAGE_SECTION_HEADER p_first_sect = IMAGE_FIRST_SECTION(nt_head);
	for (PIMAGE_SECTION_HEADER p_section = p_first_sect; p_section < p_first_sect + nt_head->FileHeader.NumberOfSections; p_section++)
		if (rva >= p_section->VirtualAddress && rva < p_section->VirtualAddress + p_section->Misc.VirtualSize)
			return (PUCHAR)local_image + p_section->PointerToRawData + (rva - p_section->VirtualAddress);

	return NULL;
}

uintptr_t resolve_func_addr(LPCSTR modname, LPCSTR modfunc)
{
	HMODULE h_module = LoadLibraryExA(modname, NULL, DONT_RESOLVE_DLL_REFERENCES);
	uintptr_t func_offset = (uintptr_t)GetProcAddress(h_module, modfunc);
	func_offset -= (uintptr_t)h_module;
	FreeLibrary(h_module);

	return func_offset;
}

BOOL relocate_image(PVOID p_remote_img, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
	struct reloc_entry
	{
		ULONG to_rva;
		ULONG size;
		struct
		{
			WORD offset : 12;
			WORD type : 4;
		} item[1];
	};

	uintptr_t delta_offset = (uintptr_t)p_remote_img - nt_head->OptionalHeader.ImageBase;
	if (!delta_offset) return true; else if (!(nt_head->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return false;
	reloc_entry* reloc_ent = (reloc_entry*)rva_va(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_head, p_local_img);
	uintptr_t reloc_end = (uintptr_t)reloc_ent + nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (reloc_ent == nullptr)
		return true;

	while ((uintptr_t)reloc_ent < reloc_end && reloc_ent->size)
	{
		DWORD records_count = (reloc_ent->size - 8) >> 1;
		for (DWORD i = 0; i < records_count; i++)
		{
			WORD fix_type = (reloc_ent->item[i].type);
			WORD shift_delta = (reloc_ent->item[i].offset) % 4096;

			if (fix_type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (fix_type == IMAGE_REL_BASED_HIGHLOW || fix_type == IMAGE_REL_BASED_DIR64)
			{
				uintptr_t fix_va = (uintptr_t)rva_va(reloc_ent->to_rva, nt_head, p_local_img);

				if (!fix_va)
					fix_va = (uintptr_t)p_local_img;

				*(uintptr_t*)(fix_va + shift_delta) += delta_offset;
			}
		}

		reloc_ent = (reloc_entry*)((LPBYTE)reloc_ent + reloc_ent->size);
	} return true;
}

BOOL resolve_import(DWORD thread_id, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
	PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)rva_va(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_head, p_local_img);
	if (!nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) return true;

	LPSTR module_name = NULL;
	while ((module_name = (LPSTR)rva_va(import_desc->Name, nt_head, p_local_img)))
	{
		uintptr_t base_image;
		base_image = call_remote_load_library(thread_id, module_name);

		if (!base_image)
			return false;

		PIMAGE_THUNK_DATA ih_data = (PIMAGE_THUNK_DATA)rva_va(import_desc->FirstThunk, nt_head, p_local_img);
		while (ih_data->u1.AddressOfData)
		{
			if (ih_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				ih_data->u1.Function = base_image + resolve_func_addr(module_name, (LPCSTR)(ih_data->u1.Ordinal & 0xFFFF));
			else
			{
				IMAGE_IMPORT_BY_NAME* ibn = (PIMAGE_IMPORT_BY_NAME)rva_va(ih_data->u1.AddressOfData, nt_head, p_local_img);
				ih_data->u1.Function = base_image + resolve_func_addr(module_name, (LPCSTR)ibn->Name);
			} ih_data++;
		} import_desc++;
	} return true;
}

void write_sections(PVOID p_module_base, PVOID local_image, PIMAGE_NT_HEADERS nt_head)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);
	for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
	{
		driver().write_memory_ex((PVOID)((uintptr_t)p_module_base + section->VirtualAddress), (PVOID)((uintptr_t)local_image + section->PointerToRawData), section->SizeOfRawData);
	}
}

void erase_discardable_sect(PVOID p_module_base, PIMAGE_NT_HEADERS nt_head)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);
	for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
	{
		if (section->SizeOfRawData == 0)
			continue;

		if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
		{
			PVOID zero_memory = VirtualAlloc(NULL, section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			driver().write_memory_ex((PVOID)((uintptr_t)p_module_base + section->VirtualAddress), zero_memory, section->SizeOfRawData);
			VirtualFree(zero_memory, 0, MEM_FREE/*mem_release*/);
		}
	}
}

string Aes256DecryptString(string str, string pw)
{
	CkCrypt2 crypt;
	crypt.put_CryptAlgorithm(xorstr_("aes"));
	crypt.put_CipherMode(xorstr_("cbc"));
	crypt.put_KeyLength(256);
	crypt.put_Charset(xorstr_("utf-8"));
	crypt.put_EncodingMode(xorstr_("base64"));
	crypt.SetSecretKeyViaPassword(pw.c_str());
	string ret(crypt.decryptStringENC(str.c_str()));
	return ret;
}

extern c_crypto crypto;
void SendLog(const char* Username, const char* Value)
{
	//VMProtectBeginUltra("SendLog");
	TCHAR compname[128];
	DWORD bufCharCount = 128;
	GetComputerNameA(compname, &bufCharCount);

	c_lw_http	lw_http;
	c_lw_httpd	lw_http_d;
	lw_http_d.add_field(xorstr_("type"), xorstr_("log"));
	lw_http_d.add_field(xorstr_("aid"), crypto.aid.c_str());
	lw_http_d.add_field(xorstr_("apikey"), crypto.apikey.c_str());
	lw_http_d.add_field(xorstr_("secret"), crypto.secret.c_str());
	lw_http_d.add_field(xorstr_("username"), Username);
	lw_http_d.add_field(xorstr_("pcuser"), compname);
	lw_http_d.add_field(xorstr_("action"), Value);

	std::string xstr = xorstr_("q5+P6WrvPdIzNXC8zrOIsG1IsyCiR2QHUmv6kwJb+1I=");//api.auth.gg/v1
	xstr = Aes256DecryptString(xstr, xorstr_("ppv^"));
	string s_reply;
	lw_http.post(xstr, s_reply.c_str(), lw_http_d);
	lw_http_d.clear();
	xstr.clear();
	s_reply.clear();
	RtlSecureZeroMemory(&xstr, sizeof(xstr));
	RtlSecureZeroMemory(&Value, sizeof(Value));
	RtlSecureZeroMemory(&s_reply, sizeof(s_reply));
	//VMProtectEnd();
}

size_t writeFunction(void* ptr, size_t size, size_t nmemb, std::string* data) {
	data->append((char*)ptr, size * nmemb);
	return size * nmemb;
}

std::string curlGetRequestt(const string& url)
{
	auto curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url.data());
		curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 1L);
		curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

		std::string response_string;
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		curl = NULL;
		return response_string;
	}
}

bool DecryptAes256File(void* data, int size, const char* save_path)
{
	remove(save_path);	
	CkCrypt2 crypt;
	void* rawObj = reinterpret_cast<void*>(data);
	CkByteData pObj;
	pObj.append2(rawObj, size);
	crypt.put_CryptAlgorithm(xorstr_("aes"));
	crypt.put_CipherMode(xorstr_("ecb"));
	crypt.put_KeyLength(256);
	crypt.put_HashAlgorithm(xorstr_("sha256"));
	auto brra = xorstr_("acknex_mainwin");
	crypt.SetSecretKeyViaPassword(brra);
	RtlSecureZeroMemory(brra, sizeof(brra));
	CkByteData DecObj;
	crypt.DecryptBytes(pObj, DecObj);
	bool bSave = DecObj.saveFile(save_path);
	delete[] DecObj.removeData();
	delete[] pObj.removeData();
	return bSave;
}


std::string currentDateTime() {
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	strftime(buf, sizeof(buf), xorstr_(" [%m.%d.%Y %X] "), &tstruct);

	return buf;
}
void run_us_admin(std::string sz_command, bool show)
{
	ShellExecuteA(NULL, xorstr_("runas"), xorstr_("cmd"), std::string(xorstr_("/c ") + sz_command).c_str(), NULL, show);
}
extern void start_driver();

void VANZ(uint64_t addr, uint64_t size, DWORD protect)
{
	driver().protect_memory_ex((uint64_t)addr, size, &protect);
}
void SetCommand(const char* commandXD) {
	//char command[] = commandXD;
	char windir[260];
	GetSystemDirectoryA(windir, MAX_PATH);
	char cmdline[MAX_PATH + 50];
	string tamamla = string(windir) + "\\cmd.exe /c %s";
	sprintf(cmdline, tamamla.c_str(), commandXD);

	STARTUPINFOA startInf;//Del /S /F /Q %windir%\Prefetch
	memset(&startInf, 0, sizeof startInf);
	startInf.cb = sizeof(startInf);

	PROCESS_INFORMATION procInf;
	memset(&procInf, 0, sizeof procInf);
	BOOL b = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
		NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &startInf, &procInf);
	DWORD dwErr = 0;
	if (b)
	{
		WaitForSingleObject(procInf.hProcess, 30000);
		GetExitCodeProcess(procInf.hProcess, &dwErr);
		TerminateProcess(procInf.hProcess, 0);
		CloseHandle(procInf.hProcess);		
	}
	else
	{
		dwErr = GetLastError();
	}
	if (dwErr)
	{
		//wprintf(L"Command failed.Error % d\n", dwErr);
	}	
}

void xprvboooooooooom() {//public hack

	auto c_str5 = string(currentDateTime() + xorstr_("Waiting for game.\n"));
	print::set_text(c_str5.c_str(), White);
	RtlSecureZeroMemory(&c_str5, sizeof(c_str5));

	DWORD thread_id;

	auto c_uwind = xorstr_("UnrealWindow");
	DWORD process_id = get_process_id_and_thread_id_by_window_class(c_uwind, &thread_id);
	if (process_id != 0 && thread_id != 0)
	{
		RtlSecureZeroMemory(c_uwind, sizeof(c_uwind));
		auto c_str6 = string(currentDateTime() + xorstr_("Game found! Injecting.."));
		print::set_text(c_str6.c_str(), White);
		RtlSecureZeroMemory(&c_str6, sizeof(c_str6));

		//Sleep(1000);
		driver().attach_process(process_id);
		// parse nt header
		PVOID CheatBytes = get_dll_by_file(L"test.dll");//dll path
		PIMAGE_NT_HEADERS dll_nt_head = RtlImageNtHeader(CheatBytes);
		if (!dll_nt_head) {
			printf(xorstr_("Error Code: 01\n"));
			Sleep(5000);
			exit(43);
		}

		PVOID64 allocate_base = driver().alloc_memory_ex(dll_nt_head->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
		auto endAddr = (uint64_t)((uint64_t)allocate_base + dll_nt_head->OptionalHeader.SizeOfImage);



		//Van128 Bypass :)
		VANZ((uint64_t)allocate_base, 1024, PAGE_READWRITE);
		VANZdud((uint64_t)endAddr - 30000, 1024, PAGE_READWRITE);

		// fix reloc
		if (!relocate_image(allocate_base, CheatBytes, dll_nt_head))
		{
			auto c_str9 = string(currentDateTime() + xorstr_("Reloc Failed!"));
			print::set_text(c_str9.c_str(), LightRed);
			RtlSecureZeroMemory(&c_str9, sizeof(c_str9));
			VirtualFree(CheatBytes, 0, MEM_RELEASE);
			driver().free_memory_ex(allocate_base);
			Sleep(5000);
			exit(43);

		}

		// fix iat
		if (!resolve_import(thread_id, CheatBytes, dll_nt_head))
		{
			auto c_str10 = string(currentDateTime() + xorstr_("IAT Failed!"));
			print::set_text(c_str10.c_str(), LightRed);
			RtlSecureZeroMemory(&c_str10, sizeof(c_str10));
			driver().free_memory_ex(allocate_base);
			Sleep(5000);
			exit(43);
		}
		write_sections(allocate_base, CheatBytes, dll_nt_head);
		call_dll_main(thread_id, allocate_base, dll_nt_head, true);
		driver().free_memory_ex(allocate_base);
		erase_discardable_sect(allocate_base, dll_nt_head);
		VirtualFree(CheatBytes, 0, MEM_RELEASE);
		exit(43);
	}
}
			
	
