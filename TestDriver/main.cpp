#include <iostream>
#include "driver.h"
#include <string>
#include <fstream>
#include <vector>

std::vector<BYTE> ReadFileToBuffer(const std::wstring& filePath) {
	std::ifstream file(filePath, std::ios::binary | std::ios::ate);
	if (!file) {
		throw std::runtime_error("Failed to open file");
	}

	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<BYTE> buffer(size);
	if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
		throw std::runtime_error("Failed to read file");
	}

	return buffer;
}

auto GetTextHashW(PCWSTR Str) -> UINT {

	UINT32 Hash = NULL;

	while (Str != NULL && *Str) {

		Hash = (UINT32)(65599 * (Hash + (*Str++) + (*Str > 64 && *Str < 91 ? 32 : 0)));
	}

	return Hash;
}

int main()
{
	std::wstring dllPath = L"MdayS.dll";

	// 读取 DLL 文件内容到缓冲区
	std::vector<BYTE> dllBuffer;
	try {
		dllBuffer = ReadFileToBuffer(dllPath);
	}
	catch (const std::exception& e) {
		MessageBox(NULL, L"Failed to read DLL file", L"Error", MB_ICONERROR);
		return 1;
	}


	driver d;
	if (!d.init())
	{
		return 1;
	}
	if (d.verify())
	{
		printf("验证成功\n");
	}
	driver::INJECT_DATA data{ 0 };
	
	ZeroMemory(&data, sizeof(data));

	data.InjectHash = GetTextHashW(L"GTA5.exe");
	data.InjectBits = 64;
	data.InjectData = dllBuffer.data();
	data.InjectMode = 0;
	data.InjectSize = dllBuffer.size();
	d.inject(&data, sizeof(data));
	
	std::cin.get();

	ZeroMemory(&data, sizeof(data));
	d.inject(&data, 0);
	return 0;
}