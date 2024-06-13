#pragma once

#include <wsk.h>

extern LONG WSKSocketsState;

extern WSK_PROVIDER_NPI WSKProviderNpi;

extern WSK_REGISTRATION WSKRegistration;

extern WSK_CLIENT_DISPATCH WSKClientDispatch;

auto WSKStartup()->NTSTATUS;

auto WSKCleanup()->NTSTATUS;

auto WSKCompletionRoutine(PDEVICE_OBJECT, PIRP, PKEVENT)->NTSTATUS;

auto WSKInitData(PIRP*, PKEVENT)->NTSTATUS;

auto WSKInitBuffer(LPVOID, SIZE_T, PWSK_BUF)->NTSTATUS;

auto WSKFreeBuffer(PWSK_BUF)->NTSTATUS;

auto WSKCreateSocket(PWSK_SOCKET*, ADDRESS_FAMILY, USHORT, ULONG, ULONG)->NTSTATUS;

auto WSKCloseSocket(PWSK_SOCKET)->NTSTATUS;

auto WSKConnect(PWSK_SOCKET, PSOCKADDR_IN)->NTSTATUS;

auto WSKSend(PWSK_SOCKET, LPVOID, SIZE_T, ULONG)->LONG;

auto WSKRecv(PWSK_SOCKET, LPVOID, SIZE_T, ULONG)->LONG;

auto WSKBind(PWSK_SOCKET, PSOCKADDR_IN)->NTSTATUS;

auto HttpPost(ULONG, ULONG, ULONG, ULONG, SHORT, LPVOID, SIZE_T, LPVOID, SIZE_T)->NTSTATUS;