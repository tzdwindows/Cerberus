// Architect: tzdwindows 7
// etw_consumer: 用户态 ETW ThreatIntelligence consumer 实现
#include "etw_consumer.h"
#include "process_protect.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>   // EVENT_RECORD, PROCESS_TRACE_MODE_*
#include <cstdio>
#include <cstring>
#include <cstdlib>

#pragma comment(lib, "advapi32.lib")

// ThreatInt provider GUID — 驱动 g_ThreatIntGuid 原始字节
//   raw: 7C 89 E1 F4 5D BB 68 56 F1 D8 04 0F 4D 8D D3 44
//   GUID: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
static const GUID g_ThreatIntGuid = {
    0xF4E1897C, 0xBB5D, 0x5668,
    {0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44}
};

// 标准 Microsoft ThreatIntelligence provider GUID (备选)
//   {F4E8917C-BB5D-5668-91F1-D80404F4D844}
static const GUID g_ThreatIntGuidStd = {
    0xF4E8917C, 0xBB5D, 0x5668,
    {0x91, 0xF1, 0xD8, 0x04, 0x04, 0xF4, 0xD8, 0x44}
};

static const WCHAR* g_sessionName = L"TZD_ThreatInt";

static TRACEHANDLE g_sessionHandle = 0;
static TRACEHANDLE g_traceHandle = INVALID_PROCESSTRACE_HANDLE;
static HANDLE g_consumerThread = NULL;
static volatile LONG g_consumerRunning = 0;
static unsigned long g_armedPid = 0;
static volatile LONG g_eventCount = 0;
static volatile LONG g_suspiciousCount = 0;
static int g_pplWasSet = 0;

// ─── 事件回调 ────────────────────────────────────────────────────────────
static VOID WINAPI event_callback(PEVENT_RECORD er)
{
    InterlockedIncrement(&g_eventCount);

    // 只关心被武装进程的事件
    if (g_armedPid && er->EventHeader.ProcessId != (ULONG)g_armedPid)
        return;

    USHORT opcode = er->EventHeader.EventDescriptor.Opcode;
    USHORT eventId = er->EventHeader.EventDescriptor.Id;
    UCHAR level = er->EventHeader.EventDescriptor.Level;
    GUID provId = er->EventHeader.ProviderId;

    // hex dump UserData 前 64 字节 (ThreatInt 事件含 syscall 参数)
    char hex[300]; hex[0] = 0;
    int hp = 0;
    if (er->UserData && er->UserDataLength > 0) {
        int dumpLen = er->UserDataLength < 64 ? er->UserDataLength : 64;
        for (int i = 0; i < dumpLen && hp < 280; i++)
            hp += snprintf(hex + hp, sizeof(hex) - hp, "%02X ",
                           ((const unsigned char*)er->UserData)[i]);
    }

    InterlockedIncrement(&g_suspiciousCount);

    fprintf(stderr,
            "[TZD-ETW] THREAT EVENT pid=%lu tid=%lu opcode=%u eventId=%u "
            "level=%u dataLen=%u data=[%s] (total=%ld)\n",
            (unsigned long)er->EventHeader.ProcessId,
            (unsigned long)er->EventHeader.ThreadId,
            (unsigned int)opcode, (unsigned int)eventId,
            (unsigned int)level,
            (unsigned int)er->UserDataLength,
            hex,
            (long)InterlockedExchangeAdd(&g_suspiciousCount, 0));
    fflush(stderr);

    // 直接终止进程 (不等告警轮询; ThreatInt 事件 = 内核已观测到可疑 syscall)
    fprintf(stderr,
            "[TZD-ETW] COMPROMISED — TerminateProcess(0x5C) (threatInt event from armed pid)\n");
    fflush(stderr);
    TerminateProcess(GetCurrentProcess(), 0x5C);
}

// ─── 消费者线程 ──────────────────────────────────────────────────────────
static DWORD WINAPI consumer_thread(LPVOID)
{
    // ProcessTrace 阻塞直到 CloseTrace 被调用
    ULONG status = ProcessTrace(&g_traceHandle, 1, NULL, NULL);
    fprintf(stderr, "[TZD-ETW] ProcessTrace ended: %lu\n", status);
    fflush(stderr);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// ─── Public API ──────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════

bool etw_consumer_start(unsigned long armedPid, int setPpl)
{
    g_armedPid = armedPid;
    g_eventCount = 0;
    g_suspiciousCount = 0;
    g_pplWasSet = 0;

    // 1. 设 PPL Antimalware Light (ThreatInt 订阅需要; 驱动直写 EPROCESS)
    if (setPpl && armedPid) {
        bool pplOk = process_protect_kernel_set_ppl(armedPid, 0x61, 0x0F);
        if (pplOk) {
            g_pplWasSet = 1;
            fprintf(stderr, "[TZD-ETW] PPL Antimalware Light set (pid=%lu)\n", armedPid);
        } else {
            fprintf(stderr, "[TZD-ETW] PPL set failed — ThreatInt subscribe may be denied\n");
        }
        fflush(stderr);
    }

    // 2. 开始 trace session (real-time)
    //    先停残留 session (上次测试未清理 → StartTraceW 返回 ALREADY_EXISTS → handle 无效)
    size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + 512;
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
    if (!props) return false;
    memset(props, 0, propsSize);
    props->Wnode.BufferSize = (ULONG)propsSize;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW((TRACEHANDLE)0, g_sessionName, props, EVENT_TRACE_CONTROL_STOP);
    // 重新 memset (STOP 可能填充了字段)
    memset(props, 0, propsSize);
    props->Wnode.BufferSize = (ULONG)propsSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  // QPC
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->MaximumBuffers = 64;

    ULONG status = StartTraceW(&g_sessionHandle, g_sessionName, props);
    if (status != ERROR_SUCCESS) {
        fprintf(stderr, "[TZD-ETW] StartTraceW failed: %lu\n", status);
        free(props);
        return false;
    }

    // 3. 启用 ThreatInt provider (先试驱动 GUID, 再试标准 GUID)
    status = EnableTraceEx2(g_sessionHandle, &g_ThreatIntGuid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE,     // level
                            0xFFFFFFFFFFFFFFFFULL,   // keyword any (全开)
                            0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        fprintf(stderr, "[TZD-ETW] EnableTraceEx2 (driver GUID) failed: %lu", status);
        if (status == ERROR_ACCESS_DENIED)
            fprintf(stderr, " (ACCESS_DENIED: PPL Antimalware Light required)");
        fprintf(stderr, " — trying standard GUID\n");
        fflush(stderr);

        status = EnableTraceEx2(g_sessionHandle, &g_ThreatIntGuidStd,
                                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_VERBOSE,
                                0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
        if (status != ERROR_SUCCESS) {
            fprintf(stderr, "[TZD-ETW] EnableTraceEx2 (standard GUID) also failed: %lu", status);
            if (status == ERROR_ACCESS_DENIED)
                fprintf(stderr, " (PPL required — consumer cannot subscribe without PPL Antimalware Light)");
            fprintf(stderr, "\n");
            fflush(stderr);
            ControlTraceW(g_sessionHandle, g_sessionName, props, EVENT_TRACE_CONTROL_STOP);
            g_sessionHandle = 0;
            free(props);
            return false;
        }
    }

    fprintf(stderr, "[TZD-ETW] ThreatInt provider enabled (level=verbose kw=full)\n");
    fflush(stderr);

    // 4. 打开 trace 供处理 (real-time + event record callback)
    EVENT_TRACE_LOGFILEW logFile;
    memset(&logFile, 0, sizeof(logFile));
    logFile.LoggerName = (LPWSTR)g_sessionName;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)event_callback;

    g_traceHandle = OpenTraceW(&logFile);
    if (g_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        fprintf(stderr, "[TZD-ETW] OpenTraceW failed: %lu\n", GetLastError());
        fflush(stderr);
        ControlTraceW(g_sessionHandle, g_sessionName, props, EVENT_TRACE_CONTROL_STOP);
        g_sessionHandle = 0;
        free(props);
        return false;
    }

    // 5. 启动消费者线程 (ProcessTrace 阻塞在此线程)
    InterlockedExchange(&g_consumerRunning, 1);
    g_consumerThread = CreateThread(NULL, 0, consumer_thread, NULL, 0, NULL);
    if (!g_consumerThread) {
        fprintf(stderr, "[TZD-ETW] CreateThread failed: %lu\n", GetLastError());
        CloseTrace(g_traceHandle);
        g_traceHandle = INVALID_PROCESSTRACE_HANDLE;
        ControlTraceW(g_sessionHandle, g_sessionName, props, EVENT_TRACE_CONTROL_STOP);
        g_sessionHandle = 0;
        free(props);
        return false;
    }

    fprintf(stderr, "[TZD-ETW] Consumer started (armedPid=%lu session=0x%llx trace=0x%llx)\n",
            armedPid, (unsigned long long)g_sessionHandle, (unsigned long long)g_traceHandle);
    fflush(stderr);

    free(props);
    return true;
}

bool etw_consumer_stop(void)
{
    InterlockedExchange(&g_consumerRunning, 0);

    // 先关闭 trace handle → ProcessTrace 返回 → 消费者线程退出
    if (g_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_traceHandle);
        g_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    // 停止 trace session
    if (g_sessionHandle) {
        size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + 512;
        EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
        if (props) {
            memset(props, 0, propsSize);
            props->Wnode.BufferSize = (ULONG)propsSize;
            ControlTraceW(g_sessionHandle, g_sessionName, props, EVENT_TRACE_CONTROL_STOP);
            free(props);
        }
        g_sessionHandle = 0;
    }

    // 等消费者线程退出
    if (g_consumerThread) {
        WaitForSingleObject(g_consumerThread, 3000);
        CloseHandle(g_consumerThread);
        g_consumerThread = NULL;
    }

    // 恢复 PPL (若之前设过)
    if (g_pplWasSet && g_armedPid) {
        process_protect_kernel_set_ppl(g_armedPid, 0, 0);
        g_pplWasSet = 0;
    }

    fprintf(stderr, "[TZD-ETW] Consumer stopped (events=%ld suspicious=%ld)\n",
            g_eventCount, g_suspiciousCount);
    fflush(stderr);
    return true;
}
