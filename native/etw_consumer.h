// Architect: tzdwindows 7
// etw_consumer: 用户态 ETW ThreatIntelligence consumer
//
// 驱动 (tzd_ppl_drv.sys) 已强制启用 ThreatInt provider 发射 (ARM_ETW_TI → 写
// EtwThreatIntProvRegHandle GuidEntry 的 kwmask/count)。但发射的事件只投递到
// 已开启 trace session 且 EnableTraceEx2 启用该 provider 的消费者。
//
// Windows 限制: ThreatInt provider 订阅需要 PPL Antimalware Light。
//   消费者启动前先通过驱动 SET_PPL 设 Protection=0x61 + SigLevel=0x0F。
//   若失败 (PPL 不足), EnableTraceEx2 返回 ERROR_ACCESS_DENIED → 回退告警轮询。
//
// 事件处理: ThreatInt 事件含 NtProtectVirtualMemory/NtAllocateVirtualMemory/
//   NtMapViewOfSection/NtCreateThreadEx 等。检查事件来自被武装进程 → 标记 compromised。
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// 启动 ETW ThreatInt consumer。
//   armedPid : 被武装进程 PID (只关心此 PID 的事件; 0 = 全局)
//   setPpl   : 是否先设 PPL Antimalware Light (ThreatInt 订阅需要; false 则跳过)
// 返回 true=成功。
bool etw_consumer_start(unsigned long armedPid, int setPpl);

// 停止 consumer (关闭 trace + 恢复 PPL)。
bool etw_consumer_stop(void);

#ifdef __cplusplus
}
#endif
