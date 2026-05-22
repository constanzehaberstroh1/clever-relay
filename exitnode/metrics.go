package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// System Metrics Collector
//
// Reads CPU and memory usage from Linux /proc filesystem for real-time
// container monitoring. Falls back to Go runtime stats on non-Linux systems.
// ──────────────────────────────────────────────────────────────────────────────

// SystemMetrics holds real-time container resource data.
type SystemMetrics struct {
	// Memory
	MemTotalMB    float64 `json:"mem_total_mb"`
	MemUsedMB     float64 `json:"mem_used_mb"`
	MemFreeMB     float64 `json:"mem_free_mb"`
	MemUsagePercent float64 `json:"mem_usage_percent"`

	// Go runtime
	GoAllocMB     float64 `json:"go_alloc_mb"`
	GoHeapMB      float64 `json:"go_heap_mb"`
	GoStackMB     float64 `json:"go_stack_mb"`
	GoSysMB       float64 `json:"go_sys_mb"`
	GCPauseMs     float64 `json:"gc_pause_ms"`
	NumGC         uint32  `json:"num_gc"`
	Goroutines    int     `json:"goroutines"`

	// CPU
	CPUUsagePercent float64 `json:"cpu_usage_percent"`

	// Uptime
	Uptime        string  `json:"uptime"`
	UptimeSeconds float64 `json:"uptime_seconds"`
}

// prevCPU stores the previous CPU sample for delta calculation.
var (
	prevIdle  uint64
	prevTotal uint64
)

// CollectSystemMetrics gathers system resource information.
func CollectSystemMetrics() SystemMetrics {
	m := SystemMetrics{
		Goroutines:    runtime.NumGoroutine(),
		Uptime:        time.Since(startTime).Round(time.Second).String(),
		UptimeSeconds: time.Since(startTime).Seconds(),
	}

	// Go runtime memory stats
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	m.GoAllocMB = float64(mem.Alloc) / 1024 / 1024
	m.GoHeapMB = float64(mem.HeapAlloc) / 1024 / 1024
	m.GoStackMB = float64(mem.StackInuse) / 1024 / 1024
	m.GoSysMB = float64(mem.Sys) / 1024 / 1024
	m.NumGC = mem.NumGC
	if mem.NumGC > 0 {
		m.GCPauseMs = float64(mem.PauseNs[(mem.NumGC+255)%256]) / 1e6
	}

	// Linux /proc memory
	if memInfo, err := readProcMeminfo(); err == nil {
		m.MemTotalMB = memInfo.totalKB / 1024
		m.MemFreeMB = memInfo.freeKB / 1024
		m.MemUsedMB = m.MemTotalMB - m.MemFreeMB
		if m.MemTotalMB > 0 {
			m.MemUsagePercent = (m.MemUsedMB / m.MemTotalMB) * 100
		}
	}

	// Linux /proc CPU
	m.CPUUsagePercent = readCPUUsage()

	return m
}

// meminfo holds parsed /proc/meminfo values.
type meminfo struct {
	totalKB float64
	freeKB  float64
}

// readProcMeminfo parses /proc/meminfo for memory statistics.
func readProcMeminfo() (meminfo, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return meminfo{}, err
	}

	var info meminfo
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseFloat(fields[1], 64)
		switch fields[0] {
		case "MemTotal:":
			info.totalKB = val
		case "MemAvailable:", "MemFree:":
			// Prefer MemAvailable if present
			if fields[0] == "MemAvailable:" || info.freeKB == 0 {
				info.freeKB = val
			}
		}
	}
	return info, nil
}

// readCPUUsage calculates CPU usage from /proc/stat deltas.
func readCPUUsage() float64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0
	}

	// First line: cpu <user> <nice> <system> <idle> <iowait> <irq> <softirq>
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}

	var values []uint64
	for _, f := range fields[1:] {
		v, _ := strconv.ParseUint(f, 10, 64)
		values = append(values, v)
	}

	if len(values) < 4 {
		return 0
	}

	idle := values[3]
	var total uint64
	for _, v := range values {
		total += v
	}

	// Calculate delta since last sample
	deltaIdle := idle - prevIdle
	deltaTotal := total - prevTotal

	prevIdle = idle
	prevTotal = total

	if deltaTotal == 0 {
		return 0
	}

	return float64(deltaTotal-deltaIdle) / float64(deltaTotal) * 100
}

// TrafficStats holds aggregated traffic counters.
type TrafficStats struct {
	TotalBytesIn  int64 `json:"total_bytes_in"`
	TotalBytesOut int64 `json:"total_bytes_out"`
	TotalRequests int64 `json:"total_requests"`
	ActiveConns   int64 `json:"active_connections"`
}

// FormatBytes converts bytes to a human-readable string.
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
