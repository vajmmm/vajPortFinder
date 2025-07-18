package vars

import (
	"sync"
	"time"
)

type ProbeResponse struct {
	ProbeType    string        // 探测包类型
	Received     bool          // 是否收到响应
	TTL          int8          // IP包的TTL值
	Window       int16         // TCP窗口大小
	IPFlags      uint16        // IP包的标志位
	IPID         uint16        // IP包的标识符
	TCPFlags     uint8         // TCP包的标志位
	TCPOptions   []byte        // TCP选项
	ICMPType     int8          // ICMP响应类型
	ICMPCode     int8          // ICMP响应代码
	SeqNum       uint32        // TCP序列号
	AckNum       uint32        // TCP确认号
	ResponseTime time.Duration // 响应时间
	Timestamp    time.Time     // 响应时间戳
}

type OSFingerprint struct {
	IP         string                    //目标IP
	Probes     map[string]*ProbeResponse // 探测包响应特征
	FirstSeen  time.Time                 // 首次探测时间
	LastUpdate time.Time                 // 最后探测时间
	OSGuess    string                    // 操作系统猜测结果
	Confidence int                       // 猜测置信度
}

type OSProbeTask struct {
	IP         string
	Port       int
	ProbeTypes []string // 探测包类型列表
	Status     string   // "pending", "running", "completed"
}

var (
	ThreadNum         = 5
	Result            *sync.Map
	SendCounter       int64
	OSFingerprints    = make(map[string]*OSFingerprint) // key: IP地址
	OSFingerprintLock sync.RWMutex                      // 读写锁，提高并发性能
	OSProbeTasks      = make(chan *OSProbeTask, 1000)   // 探测任务队列
)

func init() {
	Result = &sync.Map{}
}

// 获取或创建OS指纹记录
func GetOrCreateOSFingerprint(ip string) *OSFingerprint {
	OSFingerprintLock.Lock()
	defer OSFingerprintLock.Unlock()

	if fp, exists := OSFingerprints[ip]; exists {
		return fp
	}

	fp := &OSFingerprint{
		IP:         ip,
		Probes:     make(map[string]*ProbeResponse),
		FirstSeen:  time.Now(),
		LastUpdate: time.Now(),
	}
	OSFingerprints[ip] = fp
	return fp
}

// 添加探测响应
func AddProbeResponse(ip string, response *ProbeResponse) {
	OSFingerprintLock.Lock()
	defer OSFingerprintLock.Unlock()

	fp := OSFingerprints[ip]
	if fp == nil {
		fp = &OSFingerprint{
			IP:        ip,
			Probes:    make(map[string]*ProbeResponse),
			FirstSeen: time.Now(),
		}
		OSFingerprints[ip] = fp
	}

	fp.Probes[response.ProbeType] = response
	fp.LastUpdate = time.Now()
}

// 获取指定IP的OS指纹
func GetOSFingerprint(ip string) (*OSFingerprint, bool) {
	OSFingerprintLock.RLock()
	defer OSFingerprintLock.RUnlock()

	fp, exists := OSFingerprints[ip]
	return fp, exists
}

// 获取所有OS指纹
func GetAllOSFingerprints() map[string]*OSFingerprint {
	OSFingerprintLock.RLock()
	defer OSFingerprintLock.RUnlock()

	result := make(map[string]*OSFingerprint)
	for k, v := range OSFingerprints {
		result[k] = v
	}
	return result
}

// 清空OS指纹数据
func ClearOSFingerprints() {
	OSFingerprintLock.Lock()
	defer OSFingerprintLock.Unlock()

	OSFingerprints = make(map[string]*OSFingerprint)
}
