package hoststats

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// DiskUsage is one volume's usage summary.
type DiskUsage struct {
	Path      string  `json:"path"`
	TotalMB   uint64  `json:"total_mb"`
	UsedMB    uint64  `json:"used_mb"`
	UsedPct   float64 `json:"used_pct"`
}

// NetIO is one NIC's traffic snapshot: totals plus per-second rates computed
// against the previous sample (the first sample after boot reports zero
// rates).
type NetIO struct {
	Name         string  `json:"name"`
	RecvTotalMB  float64 `json:"recv_total_mb"`
	SentTotalMB  float64 `json:"sent_total_mb"`
	RecvMBPS     float64 `json:"recv_mbps"`
	SentMBPS     float64 `json:"sent_mbps"`
}

// Stats is the deployment-host resource snapshot.
type Stats struct {
	Timestamp string  `json:"timestamp"`
	CPUUsedPct float64 `json:"cpu_used_pct"`
	MemTotalMB uint64 `json:"mem_total_mb"`
	MemUsedMB  uint64  `json:"mem_used_mb"`
	MemUsedPct float64 `json:"mem_used_pct"`
	Disks     []DiskUsage `json:"disks"`
	// Net carries per-NIC traffic (loopback and zero-traffic interfaces
	// excluded; sorted by total volume, primary first).
	Net       []NetIO     `json:"net"`
	UptimeSec uint64      `json:"uptime_sec"`
	// Runtime self-observation.
	Goroutines int    `json:"goroutines"`
	HeapAllocMB float64 `json:"heap_alloc_mb"`
	NumCPU     int    `json:"num_cpu"`
	// Container awareness: container=true means the process detected a
	// container environment; when cgroup v2 limits are readable the memory
	// and CPU numbers are scoped to the container, otherwise they are the
	// host's (container_note explains which).
	Container     bool    `json:"container"`
	ContainerNote string  `json:"container_note,omitempty"`
	CGCPULimit    float64 `json:"cgroup_cpu_limit_cores,omitempty"`
	CGMemLimitMB  uint64  `json:"cgroup_mem_limit_mb,omitempty"`
	CGMemUsedMB   uint64  `json:"cgroup_mem_used_mb,omitempty"`
}

// netSample caches the previous per-NIC byte counters so Snapshot can report
// rates without the caller tracking state.
var (
	netMu      sync.Mutex
	netPrev    map[string][2]uint64 // name → [recv, sent]
	netPrevAt  time.Time
)

// sampleNet collects per-NIC counters and derives MB/s rates vs the previous
// sample. Loopback and disconnected interfaces are skipped.
func sampleNet() []NetIO {
	nc, err := net.IOCounters(true)
	if err != nil {
		return nil
	}
	now := time.Now()
	netMu.Lock()
	defer netMu.Unlock()
	elapsed := 0.0
	if !netPrevAt.IsZero() {
		elapsed = now.Sub(netPrevAt).Seconds()
	}
	out := make([]NetIO, 0, len(nc))
	for _, n := range nc {
		name := strings.ToLower(n.Name)
		if name == "lo" || name == "loopback" || (n.BytesRecv == 0 && n.BytesSent == 0) {
			continue
		}
		io := NetIO{
			Name:        n.Name,
			RecvTotalMB: float64(n.BytesRecv) / (1 << 20),
			SentTotalMB: float64(n.BytesSent) / (1 << 20),
		}
		if prev, ok := netPrev[n.Name]; ok && elapsed > 0 {
			io.RecvMBPS = round2(float64(n.BytesRecv-prev[0]) / (1 << 20) / elapsed)
			io.SentMBPS = round2(float64(n.BytesSent-prev[1]) / (1 << 20) / elapsed)
		}
		if netPrev == nil {
			netPrev = map[string][2]uint64{}
		}
		netPrev[n.Name] = [2]uint64{n.BytesRecv, n.BytesSent}
		out = append(out, io)
	}
	netPrevAt = now
	// Primary NIC first (largest total volume).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if a.RecvTotalMB+a.SentTotalMB >= b.RecvTotalMB+b.SentTotalMB {
				break
			}
			out[j-1], out[j] = b, a
		}
	}
	return out
}

func round2(v float64) float64 { return float64(int(v*100+0.5)) / 100 }

// Snapshot samples host resources. auditDir (the data volume) is the disk
// reported first; it may be empty.
func Snapshot(auditDir string) (*Stats, error) {
	st := &Stats{Timestamp: time.Now().Format(time.RFC3339)}

	if pct, err := cpu.Percent(0, false); err == nil && len(pct) > 0 {
		st.CPUUsedPct = round1(pct[0])
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		st.MemTotalMB = vm.Total >> 20
		st.MemUsedMB = vm.Used >> 20
		st.MemUsedPct = round1(vm.UsedPercent)
	}
	st.NumCPU = runtime.NumCPU()
	st.Goroutines = runtime.NumGoroutine()
	st.HeapAllocMB = round1(float64(heapBytes()) / (1 << 20))
	if hi, err := host.Info(); err == nil {
		st.UptimeSec = hi.Uptime
	}

	// Container detection + cgroup v2 scoping (Linux only).
	if isContainer() {
		st.Container = true
		applyCgroupV2(st)
	}

	// Disks: the data volume first, then the root/filesystem of the process.
	seen := map[string]bool{}
	for _, p := range []string{auditDir, string(os.PathSeparator)} {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if du, err := disk.Usage(p); err == nil {
			st.Disks = append(st.Disks, DiskUsage{
				Path:    p,
				TotalMB: du.Total >> 20,
				UsedMB:  du.Used >> 20,
				UsedPct: round1(du.UsedPercent),
			})
		}
	}

	// NIC traffic (totals + rates vs the previous sample).
	st.Net = sampleNet()
	return st, nil
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

func heapBytes() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// isContainer detects the common container markers (docker/podman/lxc/k8s).
func isContainer() bool {
	for _, p := range []string{
		"/.dockerenv",
		"/run/.containerenv",
		"/run/systemd/container",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	// cgroup v1 controller path mentioning a container id.
	if b, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		s := string(b)
		if strings.Contains(s, "/docker/") || strings.Contains(s, "/containerd/") ||
			strings.Contains(s, "/kubepods/") || strings.Contains(s, "/lxc/") {
			return true
		}
	}
	return false
}

// applyCgroupV2 reads the cgroup v2 CPU/memory limits and current usage when
// available (/sys/fs/cgroup). Best effort: missing files are simply skipped
// and the host-level numbers remain in place.
func applyCgroupV2(st *Stats) {
	const base = "/sys/fs/cgroup"
	if b, err := os.ReadFile(base + "/cpu.max"); err == nil {
		// Format: "max 100000" or "200000 100000" (quota period, us).
		f := strings.Fields(string(b))
		if len(f) == 2 && f[0] != "max" {
			if quota, err1 := strconv.ParseFloat(f[0], 64); err1 == nil {
				if period, err2 := strconv.ParseFloat(f[1], 64); err2 == nil && period > 0 {
					st.CGCPULimit = round1(quota / period)
				}
			}
		}
	}
	if b, err := os.ReadFile(base + "/memory.max"); err == nil {
		s := strings.TrimSpace(string(b))
		if s != "max" {
			if v, err := strconv.ParseUint(s, 10, 64); err == nil {
				st.CGMemLimitMB = v >> 20
				// Scope memory numbers to the container when the limit is
				// lower than the host total.
				if st.MemTotalMB == 0 || st.CGMemLimitMB < st.MemTotalMB {
					if b2, err2 := os.ReadFile(base + "/memory.current"); err2 == nil {
						if used, err3 := strconv.ParseUint(strings.TrimSpace(string(b2)), 10, 64); err3 == nil {
							st.CGMemUsedMB = used >> 20
							if st.CGMemLimitMB > 0 {
								st.MemTotalMB = st.CGMemLimitMB
								st.MemUsedMB = st.CGMemUsedMB
								if st.MemTotalMB > 0 {
									st.MemUsedPct = round1(float64(st.MemUsedMB) / float64(st.MemTotalMB) * 100)
								}
							}
						}
					}
				}
			}
		}
	}
	if st.CGMemLimitMB > 0 || st.CGCPULimit > 0 {
		st.ContainerNote = "cgroup v2 limits detected; memory/CPU scoped to the container where available"
	} else {
		st.ContainerNote = "container detected; resource numbers are the host's (/proc view)"
	}
}
