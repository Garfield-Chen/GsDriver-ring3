#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <windef.h>
#include <bcrypt.h>
#include <ntimage.h>
#include <classpnp.h>
#include <ntstrsafe.h>
#include <minwindef.h>

#include "��Դ�ļ�\NativeEnums.h"
#include "��Դ�ļ�\NativeStructs.h"

#include "�����ļ�.h"
#include "ȫ�ֱ���.h"
#include "��������.h"

#include "��Դ�ļ�\\VMProtect\\VMProtectDDK.h"

extern "C" auto DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)->NTSTATUS;