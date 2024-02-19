// ConsoleApplication2.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "driver.h"

int main()
{
	driver d;
	if (!d.attach(L"notepad.exe"))
	{
		printf("附加失败");
		return 1;
	}
	if (!d.init())
	{
		return 1;
	}
	if (d.verify())
	{
		printf("验证成功\n");
	}
	uint64_t base_address = 0;
	printf("基地址: %llx\n", base_address = d.get_base_address());
	printf("模块地址: %llx\n", d.get_module_address("notepad.exe"));
	char x = 'b';
	d.read(base_address, (uint64_t)&x, 1);
	x = 'b';
	d.write1((uint64_t)&x, d.get_base_address(), 1);
	d.read(base_address, (uint64_t) & x, 1);
	printf("%c\n", x);
	auto start = GetTickCount64();
	for (size_t i = 0; i < 10000; i++)
	{
		d.read<int>(base_address);
	}
	printf("cost: %llums\n", GetTickCount64() - start);
	d.force_delete("C:\\a.txt");
	d.kill_process("explorer.exe");
	uint64_t alloc = d.alloc_memory(10, PAGE_READWRITE, FALSE);
	d.free_memory(alloc);
	driver::MOUSE_INPUT_DATA mid{ 0 };
	mid.LastX = 100;
	mid.LastY = 100;
	mid.ButtonFlags = 0;
	mid.UnitId = 1;
	d.mouse(&mid);
	d.spoof_hwid(0);
	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
