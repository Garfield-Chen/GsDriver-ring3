#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <stdlib.h>
#include <intrin.h>
#include <bcrypt.h>
#include <windef.h>
#include <ntimage.h>
#include <strsafe.h>
#include <classpnp.h>
#include <netioddk.h>
#include <ntstrsafe.h>

#include "��Դ�ļ�\NativeEnums.h"
#include "��Դ�ļ�\NativeStructs.h"

#include "ȫ�ֱ���.h"
#include "�Զ�����.h"
#include "ע�����.h"
#include "��������.h"
#include "��������.h"
#include "��������.h"
#include "ע��ص�.h"
#include "����ģ��.h"
#include "�����Ȩ.h"
#include "�ں˷���.h"
#include "���̻ص�.h"
#include "ͨѶ�ص�.h"

#include "��Դ�ļ�\\VMProtect\\VMProtectDDK.h"

extern "C" VOID DriverEntry();