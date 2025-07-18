package scanner

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	stdos "os"
	"portfinder/util"
	"portfinder/vars"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// OSScanner OS探测器
type OSScanner struct {
	target        string
	openPort      int
	closedPort    int
	fingerprintDB map[string]*OSSignature
	dbLoaded      bool
	mu            sync.RWMutex
}

// OSSignature OS签名
type OSSignature struct {
	Name        string
	Class       string
	CPE         string
	SEQ         map[string]string
	OPS         map[string]string
	WIN         map[string]string
	ECN         map[string]string
	T1          map[string]string
	T2          map[string]string
	T3          map[string]string
	T4          map[string]string
	T5          map[string]string
	T6          map[string]string
	T7          map[string]string
	U1          map[string]string
	IE          map[string]string
	MatchPoints int
}

// ProbeResult 探测结果
type ProbeResult struct {
	ProbeType    string
	Received     bool
	TTL          uint8
	WindowSize   uint16
	IPID         uint16
	IPFlags      uint16
	TCPFlags     uint8
	SeqNum       uint32
	AckNum       uint32
	TCPOptions   []byte
	ICMPType     uint8
	ICMPCode     uint8
	ResponseTime time.Duration
}

// MatchResult 匹配结果
type MatchResult struct {
	Name       string
	Score      int
	MaxScore   int
	Confidence int
	Category   string
}

var (
	osResponseMap  = make(map[string]chan *ProbeResult)
	osResponseLock sync.Mutex
	osListenerOnce sync.Once
)

// NewOSScanner 创建OS扫描器
func NewOSScanner(target string, openPort, closedPort int) *OSScanner {
	return &OSScanner{
		target:        target,
		openPort:      openPort,
		closedPort:    closedPort,
		fingerprintDB: make(map[string]*OSSignature),
	}
}

// LoadNmapOSDB 加载nmap-os-db数据库
func (os *OSScanner) LoadNmapOSDB(dbPath string) error {
	os.mu.Lock()
	defer os.mu.Unlock()

	file, err := stdos.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open OS database: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentOS *OSSignature

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过注释和空行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析Fingerprint行
		if strings.HasPrefix(line, "Fingerprint ") {
			if currentOS != nil {
				os.fingerprintDB[currentOS.Name] = currentOS
			}
			currentOS = &OSSignature{
				Name: strings.TrimPrefix(line, "Fingerprint "),
				SEQ:  make(map[string]string),
				OPS:  make(map[string]string),
				WIN:  make(map[string]string),
				ECN:  make(map[string]string),
				T1:   make(map[string]string),
				T2:   make(map[string]string),
				T3:   make(map[string]string),
				T4:   make(map[string]string),
				T5:   make(map[string]string),
				T6:   make(map[string]string),
				T7:   make(map[string]string),
				U1:   make(map[string]string),
				IE:   make(map[string]string),
			}
			continue
		}

		if currentOS == nil {
			continue
		}

		// 解析Class行
		if strings.HasPrefix(line, "Class ") {
			currentOS.Class = strings.TrimPrefix(line, "Class ")
			continue
		}

		// 解析CPE行
		if strings.HasPrefix(line, "CPE ") {
			currentOS.CPE = strings.TrimPrefix(line, "CPE ")
			continue
		}

		// 解析各种测试行
		os.parseTestLine(line, currentOS)
	}

	// 保存最后一个OS
	if currentOS != nil {
		os.fingerprintDB[currentOS.Name] = currentOS
	}

	os.dbLoaded = true
	fmt.Printf("[+] Loaded %d OS signatures from database\n", len(os.fingerprintDB))
	return scanner.Err()
}

// openFile 打开文件的辅助方法
func (os *OSScanner) openFile(path string) (*stdos.File, error) {
	return stdos.Open(path)
}

// parseTestLine 解析测试行
func (os *OSScanner) parseTestLine(line string, signature *OSSignature) {
	// 使用正则表达式解析各种测试行
	testTypes := []string{"SEQ", "OPS", "WIN", "ECN", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1", "IE"}

	for _, testType := range testTypes {
		if strings.HasPrefix(line, testType+"(") && strings.HasSuffix(line, ")") {
			content := line[len(testType)+1 : len(line)-1]
			params := os.parseParams(content)

			switch testType {
			case "SEQ":
				signature.SEQ = params
			case "OPS":
				signature.OPS = params
			case "WIN":
				signature.WIN = params
			case "ECN":
				signature.ECN = params
			case "T1":
				signature.T1 = params
			case "T2":
				signature.T2 = params
			case "T3":
				signature.T3 = params
			case "T4":
				signature.T4 = params
			case "T5":
				signature.T5 = params
			case "T6":
				signature.T6 = params
			case "T7":
				signature.T7 = params
			case "U1":
				signature.U1 = params
			case "IE":
				signature.IE = params
			}
			break
		}
	}
}

// parseParams 解析参数
func (os *OSScanner) parseParams(content string) map[string]string {
	params := make(map[string]string)
	parts := strings.Split(content, "%")

	for _, part := range parts {
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				params[kv[0]] = kv[1]
			}
		}
	}

	return params
}

// StartOSListener 启动OS探测监听器
func StartOSListener() {
	osListenerOnce.Do(func() {
		// TCP监听器
		go startTCPOSListener()
		// ICMP监听器
		go startICMPOSListener()
	})
}

// startTCPOSListener TCP OS监听器
func startTCPOSListener() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		fmt.Printf("[-] TCP OS Listener failed: %v\n", err)
		return
	}
	defer syscall.Close(fd)

	buf := make([]byte, 4096)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 40 {
			continue
		}

		result := parseIPPacket(buf[:n])
		if result != nil && result.ProbeType != "" {
			osResponseLock.Lock()
			if ch, exists := osResponseMap[result.ProbeType]; exists {
				select {
				case ch <- result:
				default:
				}
			}
			osResponseLock.Unlock()
		}
	}
}

// startICMPOSListener ICMP OS监听器
func startICMPOSListener() {
	// Windows上ICMP的协议号是1
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, 1)
	if err != nil {
		fmt.Printf("[-] ICMP OS Listener failed: %v\n", err)
		return
	}
	defer syscall.Close(fd)

	buf := make([]byte, 4096)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 28 {
			continue
		}

		result := parseICMPPacket(buf[:n])
		if result != nil {
			osResponseLock.Lock()
			if ch, exists := osResponseMap["ICMP"]; exists {
				select {
				case ch <- result:
				default:
				}
			}
			osResponseLock.Unlock()
		}
	}
}

// parseIPPacket 解析IP包
func parseIPPacket(data []byte) *ProbeResult {
	if len(data) < 20 {
		return nil
	}

	// IP头部解析
	ipHeaderLen := int(data[0]&0x0f) * 4
	if len(data) < ipHeaderLen+20 {
		return nil
	}

	ttl := data[8]
	ipID := binary.BigEndian.Uint16(data[4:6])
	ipFlags := binary.BigEndian.Uint16(data[6:8])

	// TCP头部解析
	tcpData := data[ipHeaderLen:]
	srcPort := binary.BigEndian.Uint16(tcpData[0:2])
	dstPort := binary.BigEndian.Uint16(tcpData[2:4])
	seqNum := binary.BigEndian.Uint32(tcpData[4:8])
	ackNum := binary.BigEndian.Uint32(tcpData[8:12])
	tcpHeaderLen := int(tcpData[12]>>4) * 4
	tcpFlags := tcpData[13]
	windowSize := binary.BigEndian.Uint16(tcpData[14:16])

	// 提取TCP选项
	var tcpOptions []byte
	if tcpHeaderLen > 20 && len(tcpData) >= tcpHeaderLen {
		tcpOptions = tcpData[20:tcpHeaderLen]
	}

	// 确定探测类型
	probeType := determineProbeType(srcPort, dstPort, tcpFlags)

	return &ProbeResult{
		ProbeType:    probeType,
		Received:     true,
		TTL:          ttl,
		WindowSize:   windowSize,
		IPID:         ipID,
		IPFlags:      ipFlags,
		TCPFlags:     tcpFlags,
		SeqNum:       seqNum,
		AckNum:       ackNum,
		TCPOptions:   tcpOptions,
		ResponseTime: 0, // 将在发送方计算
	}
}

// parseICMPPacket 解析ICMP包
func parseICMPPacket(data []byte) *ProbeResult {
	if len(data) < 28 {
		return nil
	}

	ipHeaderLen := int(data[0]&0x0f) * 4
	if len(data) < ipHeaderLen+8 {
		return nil
	}

	ttl := data[8]
	icmpData := data[ipHeaderLen:]
	icmpType := icmpData[0]
	icmpCode := icmpData[1]

	return &ProbeResult{
		ProbeType: "ICMP",
		Received:  true,
		TTL:       ttl,
		ICMPType:  icmpType,
		ICMPCode:  icmpCode,
	}
}

// determineProbeType 确定探测类型
func determineProbeType(srcPort, dstPort uint16, flags uint8) string {
	// 根据端口和标志位确定探测类型
	if flags&0x02 != 0 { // SYN
		return "T1"
	} else if flags&0x10 != 0 { // ACK
		return "T4"
	} else if flags&0x01 != 0 { // FIN
		return "T2"
	} else if flags == 0 { // NULL
		return "T3"
	} else if flags&0x29 != 0 { // XMAS (FIN+PSH+URG)
		return "T5"
	}
	return "UNKNOWN"
}

// DoOSDetection 执行OS探测
func (os *OSScanner) DoOSDetection() (*vars.OSFingerprint, error) {
	if !os.dbLoaded {
		return nil, fmt.Errorf("OS database not loaded")
	}

	fmt.Printf("[+] Starting OS detection for %s\n", os.target)

	// 启动监听器
	StartOSListener()

	// 存储所有探测结果
	allResults := make(map[string]*ProbeResult)

	// 执行各种探测
	probes := []struct {
		name     string
		function func() (*ProbeResult, error)
	}{
		{"T1", os.sendT1Probe},
		{"T2", os.sendT2Probe},
		{"T3", os.sendT3Probe},
		{"T4", os.sendT4Probe},
		{"T5", os.sendT5Probe},
		{"T6", os.sendT6Probe},
		{"T7", os.sendT7Probe},
		{"ECN", os.sendECNProbe},
		{"U1", os.sendUDPProbe},
		{"IE", os.sendICMPProbe},
	}

	for _, probe := range probes {
		fmt.Printf("[DEBUG] Starting %s probe...\n", probe.name)
		result, err := probe.function()
		if err != nil {
			fmt.Printf("[-] %s probe failed: %v\n", probe.name, err)
			continue
		}
		if result != nil {
			allResults[probe.name] = result
			fmt.Printf("[+] %s probe completed - TTL:%d, Win:%d, Flags:0x%02x\n",
				probe.name, result.TTL, result.WindowSize, result.TCPFlags)
		}

		// 探测间隔
		time.Sleep(100 * time.Millisecond)
	}

	// 分析结果并匹配OS
	osGuess, confidence := os.analyzeResults(allResults)

	// 创建OS指纹记录
	fingerprint := &vars.OSFingerprint{
		IP:         os.target,
		Probes:     make(map[string]*vars.ProbeResponse),
		FirstSeen:  time.Now(),
		LastUpdate: time.Now(),
		OSGuess:    osGuess,
		Confidence: confidence,
	}

	// 转换结果格式
	for probeType, result := range allResults {
		fingerprint.Probes[probeType] = &vars.ProbeResponse{
			ProbeType:    probeType,
			Received:     result.Received,
			TTL:          int8(result.TTL),
			Window:       int16(result.WindowSize),
			IPFlags:      result.IPFlags,
			IPID:         result.IPID,
			TCPFlags:     result.TCPFlags,
			TCPOptions:   result.TCPOptions,
			ICMPType:     int8(result.ICMPType),
			ICMPCode:     int8(result.ICMPCode),
			SeqNum:       result.SeqNum,
			AckNum:       result.AckNum,
			ResponseTime: result.ResponseTime,
			Timestamp:    time.Now(),
		}
	}

	// 保存到全局变量
	vars.AddProbeResponse(os.target, &vars.ProbeResponse{
		ProbeType: "OS_DETECTION",
		Received:  true,
		Timestamp: time.Now(),
	})

	fmt.Printf("[+] OS Detection completed for %s: %s (confidence: %d%%)\n",
		os.target, osGuess, confidence)

	return fingerprint, nil
}

// sendT1Probe 发送T1探测包 (SYN到开放端口)
func (os *OSScanner) sendT1Probe() (*ProbeResult, error) {
	return os.sendTCPProbe("T1", os.openPort, 0x02, false) // SYN
}

// sendT2Probe 发送T2探测包 (NULL到开放端口)
func (os *OSScanner) sendT2Probe() (*ProbeResult, error) {
	return os.sendTCPProbe("T2", os.openPort, 0x00, false) // NULL
}

// sendT3Probe 发送T3探测包 (SYN+FIN+URG+PSH到开放端口)
func (os *OSScanner) sendT3Probe() (*ProbeResult, error) {
	return os.sendTCPProbe("T3", os.openPort, 0x2B, false) // SYN+FIN+URG+PSH
}

// sendT4Probe 发送T4探测包 (ACK到开放端口)
func (os *OSScanner) sendT4Probe() (*ProbeResult, error) {
	return os.sendTCPProbe("T4", os.openPort, 0x10, false) // ACK
}

// sendT5Probe 发送T5探测包 (SYN到关闭端口)
func (os *OSScanner) sendT5Probe() (*ProbeResult, error) {
	return os.sendTCPProbe("T5", os.closedPort, 0x02, false) // SYN
}

// sendT6Probe 发送T6探测包 (ACK到关闭端口)
func (os *OSScanner) sendT6Probe() (*ProbeResult, error) {
	return os.sendTCPProbe("T6", os.closedPort, 0x10, false) // ACK
}

// sendT7Probe 发送T7探测包 (FIN+PSH+URG到关闭端口)
func (os *OSScanner) sendT7Probe() (*ProbeResult, error) {
	return os.sendTCPProbe("T7", os.closedPort, 0x29, false) // FIN+PSH+URG
}

// sendECNProbe 发送ECN探测包
func (os *OSScanner) sendECNProbe() (*ProbeResult, error) {
	return os.sendTCPProbe("ECN", os.openPort, 0x02, true) // SYN with ECN
}

// sendTCPProbe 发送TCP探测包
func (os *OSScanner) sendTCPProbe(probeType string, port int, flags uint8, ecn bool) (*ProbeResult, error) {
	srcIP, srcPort, err := util.LocalIPPort(net.ParseIP(os.target))
	if err != nil {
		return nil, err
	}

	dstIP := net.ParseIP(os.target).To4()
	if dstIP == nil {
		return nil, fmt.Errorf("invalid destination IP")
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("socket error: %v", err)
	}
	defer syscall.Close(fd)

	// 构建TCP包
	packet := os.buildTCPProbePacket(srcIP, dstIP, uint16(srcPort), uint16(port), flags, ecn)

	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], dstIP)

	// 注册响应通道
	ch := make(chan *ProbeResult, 1)
	osResponseLock.Lock()
	osResponseMap[probeType] = ch
	osResponseLock.Unlock()
	defer func() {
		osResponseLock.Lock()
		delete(osResponseMap, probeType)
		osResponseLock.Unlock()
	}()

	startTime := time.Now()
	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		return nil, fmt.Errorf("sendto failed: %v", err)
	}
	atomic.AddInt64(&vars.SendCounter, 1)

	select {
	case result := <-ch:
		result.ResponseTime = time.Since(startTime)
		return result, nil
	case <-time.After(3 * time.Second):
		return &ProbeResult{
			ProbeType:    probeType,
			Received:     false,
			ResponseTime: time.Since(startTime),
		}, nil
	}
}

// sendUDPProbe 发送UDP探测包
func (os *OSScanner) sendUDPProbe() (*ProbeResult, error) {
	srcIP, srcPort, err := util.LocalIPPort(net.ParseIP(os.target))
	if err != nil {
		return nil, err
	}

	dstIP := net.ParseIP(os.target).To4()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("UDP socket error: %v", err)
	}
	defer syscall.Close(fd)

	// 构建UDP包
	packet := os.buildUDPProbePacket(srcIP, dstIP, uint16(srcPort), uint16(os.closedPort))

	addr := syscall.SockaddrInet4{Port: os.closedPort}
	copy(addr.Addr[:], dstIP)

	ch := make(chan *ProbeResult, 1)
	osResponseLock.Lock()
	osResponseMap["U1"] = ch
	osResponseLock.Unlock()
	defer func() {
		osResponseLock.Lock()
		delete(osResponseMap, "U1")
		osResponseLock.Unlock()
	}()

	startTime := time.Now()
	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		return nil, fmt.Errorf("UDP sendto failed: %v", err)
	}
	atomic.AddInt64(&vars.SendCounter, 1)

	select {
	case result := <-ch:
		result.ResponseTime = time.Since(startTime)
		return result, nil
	case <-time.After(3 * time.Second):
		return &ProbeResult{
			ProbeType:    "U1",
			Received:     false,
			ResponseTime: time.Since(startTime),
		}, nil
	}
}

// sendICMPProbe 发送ICMP探测包
func (os *OSScanner) sendICMPProbe() (*ProbeResult, error) {
	_, _, err := util.LocalIPPort(net.ParseIP(os.target))
	if err != nil {
		return nil, err
	}

	dstIP := net.ParseIP(os.target).To4()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, 1) // Windows ICMP协议号
	if err != nil {
		return nil, fmt.Errorf("ICMP socket error: %v", err)
	}
	defer syscall.Close(fd)

	// 构建ICMP包
	packet := os.buildICMPProbePacket()

	addr := syscall.SockaddrInet4{}
	copy(addr.Addr[:], dstIP)

	ch := make(chan *ProbeResult, 1)
	osResponseLock.Lock()
	osResponseMap["ICMP"] = ch
	osResponseLock.Unlock()
	defer func() {
		osResponseLock.Lock()
		delete(osResponseMap, "ICMP")
		osResponseLock.Unlock()
	}()

	startTime := time.Now()
	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		return nil, fmt.Errorf("ICMP sendto failed: %v", err)
	}
	atomic.AddInt64(&vars.SendCounter, 1)

	select {
	case result := <-ch:
		result.ResponseTime = time.Since(startTime)
		return result, nil
	case <-time.After(3 * time.Second):
		return &ProbeResult{
			ProbeType:    "IE",
			Received:     false,
			ResponseTime: time.Since(startTime),
		}, nil
	}
}

// buildTCPProbePacket 构建TCP探测包
func (os *OSScanner) buildTCPProbePacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, flags uint8, ecn bool) []byte {
	tcpHeader := make([]byte, 28) // 20字节TCP头 + 8字节选项

	// TCP头部
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], rand.Uint32())  // 序列号
	binary.BigEndian.PutUint32(tcpHeader[8:12], rand.Uint32()) // 确认号
	tcpHeader[12] = 7 << 4                                     // 头部长度 (28字节)

	if ecn {
		tcpHeader[12] |= 0x02        // ECE
		tcpHeader[13] = flags | 0x40 // CWR
	} else {
		tcpHeader[13] = flags
	}

	binary.BigEndian.PutUint16(tcpHeader[14:16], 0x7200) // 窗口大小
	// 校验和将在后面计算
	binary.BigEndian.PutUint16(tcpHeader[18:20], 0) // 紧急指针

	// TCP选项 (MSS, Window Scale, SACK permitted, Timestamp)
	tcpHeader[20] = 0x02 // MSS
	tcpHeader[21] = 0x04
	binary.BigEndian.PutUint16(tcpHeader[22:24], 1460)
	tcpHeader[24] = 0x03 // Window Scale
	tcpHeader[25] = 0x03
	tcpHeader[26] = 0x08
	tcpHeader[27] = 0x00

	// 计算校验和
	psHeader := append([]byte{}, srcIP...)
	psHeader = append(psHeader, dstIP...)
	psHeader = append(psHeader, 0)
	psHeader = append(psHeader, syscall.IPPROTO_TCP)
	psHeader = append(psHeader, byte(len(tcpHeader)>>8), byte(len(tcpHeader)))

	cs := checksum(append(psHeader, tcpHeader...))
	binary.BigEndian.PutUint16(tcpHeader[16:18], cs)

	return tcpHeader
}

// buildUDPProbePacket 构建UDP探测包
func (os *OSScanner) buildUDPProbePacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	payload := []byte("Nmap OS Detection")
	udpHeader := make([]byte, 8+len(payload))

	binary.BigEndian.PutUint16(udpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(udpHeader[6:8], 0) // 校验和

	copy(udpHeader[8:], payload)

	// 计算校验和
	psHeader := append([]byte{}, srcIP...)
	psHeader = append(psHeader, dstIP...)
	psHeader = append(psHeader, 0)
	psHeader = append(psHeader, syscall.IPPROTO_UDP)
	psHeader = append(psHeader, byte(len(udpHeader)>>8), byte(len(udpHeader)))

	cs := checksum(append(psHeader, udpHeader...))
	binary.BigEndian.PutUint16(udpHeader[6:8], cs)

	return udpHeader
}

// buildICMPProbePacket 构建ICMP探测包
func (os *OSScanner) buildICMPProbePacket() []byte {
	icmpHeader := make([]byte, 8)

	icmpHeader[0] = 8 // Echo Request
	icmpHeader[1] = 0 // Code
	// 校验和将在后面计算
	binary.BigEndian.PutUint16(icmpHeader[4:6], uint16(rand.Intn(65536))) // ID
	binary.BigEndian.PutUint16(icmpHeader[6:8], 0)                        // Sequence

	cs := checksum(icmpHeader)
	binary.BigEndian.PutUint16(icmpHeader[2:4], cs)

	return icmpHeader
}

// analyzeResults 分析探测结果并匹配OS
func (os *OSScanner) analyzeResults(results map[string]*ProbeResult) (string, int) {
	os.mu.RLock()
	defer os.mu.RUnlock()

	fmt.Printf("[DEBUG] Starting analysis with %d results\n", len(results))

	// 首先尝试基于特征的快速识别
	quickGuess := os.performQuickClassification(results)
	if quickGuess != "" {
		fmt.Printf("[DEBUG] Quick classification result: %s\n", quickGuess)
	}

	var matches []MatchResult

	// 计算每个OS签名的匹配分数
	for osName, signature := range os.fingerprintDB {
		score, maxScore := os.calculateAdvancedMatchScore(signature, results)
		if score > 0 && maxScore > 0 {
			confidence := (score * 100) / maxScore
			if confidence > 100 {
				confidence = 100
			}

			// 确定OS类别
			category := os.getOSCategory(osName)

			matches = append(matches, MatchResult{
				Name:       osName,
				Score:      score,
				MaxScore:   maxScore,
				Confidence: confidence,
				Category:   category,
			})
		}
	}

	// 按分数排序
	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[i].Score < matches[j].Score {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}

	// 输出前5个匹配结果用于调试
	fmt.Printf("[DEBUG] Top 5 matches:\n")
	for i := 0; i < len(matches) && i < 5; i++ {
		fmt.Printf("  %d. %s (%s) - confidence: %d%%, score: %d/%d\n",
			i+1, matches[i].Name, matches[i].Category, matches[i].Confidence,
			matches[i].Score, matches[i].MaxScore)
	}

	if len(matches) == 0 {
		// 如果没有匹配，使用改进的通用匹配
		genericOS := os.performAdvancedGenericMatching(results)
		if genericOS != "" {
			fmt.Printf("[DEBUG] Using advanced generic matching: %s\n", genericOS)
			return genericOS, 65
		}
		return "Unknown", 0
	}

	// 智能结果选择
	bestMatch := os.selectBestMatch(matches, results, quickGuess)
	return bestMatch.Name, bestMatch.Confidence
}

// performQuickClassification 基于特征快速分类
func (os *OSScanner) performQuickClassification(results map[string]*ProbeResult) string {
	linuxIndicators := 0
	windowsIndicators := 0
	unixIndicators := 0

	for _, result := range results {
		if !result.Received {
			continue
		}

		// Linux典型特征
		if result.TTL >= 59 && result.TTL <= 69 {
			linuxIndicators += 3 // TTL 64左右是Linux标志
		}
		if (result.IPFlags & 0x4000) != 0 {
			linuxIndicators += 2 // DF位设置
		}
		if result.WindowSize >= 5760 || result.WindowSize == 0 {
			linuxIndicators += 1 // 大窗口或0窗口
		}

		// Windows典型特征
		if result.TTL >= 123 && result.TTL <= 133 {
			windowsIndicators += 3 // TTL 128左右
		}
		if result.WindowSize == 8192 || result.WindowSize == 16384 || result.WindowSize == 65535 {
			windowsIndicators += 2 // Windows典型窗口大小
		}

		// Unix/BSD特征
		if result.TTL >= 250 && result.TTL <= 255 {
			unixIndicators += 2 // TTL 255
		}
	}

	if linuxIndicators >= 4 {
		return "Linux"
	} else if windowsIndicators >= 4 {
		return "Windows"
	} else if unixIndicators >= 2 {
		return "Unix"
	}

	return ""
}

// calculateAdvancedMatchScore 计算高级匹配分数
func (os *OSScanner) calculateAdvancedMatchScore(signature *OSSignature, results map[string]*ProbeResult) (int, int) {
	score := 0
	maxScore := 0

	// 对每种探测类型进行精确匹配
	probeTypes := []string{"T1", "T2", "T3", "T4", "T5", "T6", "T7", "ECN", "U1", "IE"}

	for _, probeType := range probeTypes {
		result, hasResult := results[probeType]
		var testData map[string]string

		switch probeType {
		case "T1":
			testData = signature.T1
		case "T2":
			testData = signature.T2
		case "T3":
			testData = signature.T3
		case "T4":
			testData = signature.T4
		case "T5":
			testData = signature.T5
		case "T6":
			testData = signature.T6
		case "T7":
			testData = signature.T7
		case "ECN":
			testData = signature.ECN
		case "U1":
			testData = signature.U1
		case "IE":
			testData = signature.IE
		default:
			continue
		}

		if len(testData) == 0 {
			continue
		}

		probeScore, probeMaxScore := os.calculateProbeMatch(testData, result, hasResult)
		score += probeScore
		maxScore += probeMaxScore
	}

	return score, maxScore
}

// calculateProbeMatch 计算单个探测的匹配分数
func (os *OSScanner) calculateProbeMatch(testData map[string]string, result *ProbeResult, hasResult bool) (int, int) {
	score := 0
	maxScore := 0

	// 响应存在性检查 (最重要)
	if respStr, exists := testData["R"]; exists {
		maxScore += 30
		expectedResp := (respStr == "Y")
		if hasResult && result.Received == expectedResp {
			score += 30
		} else if hasResult && result.Received != expectedResp {
			score -= 10 // 响应错误扣分
		}
	}

	if !hasResult || !result.Received {
		return score, maxScore
	}

	// TTL检查
	if ttlStr, exists := testData["T"]; exists {
		maxScore += 25
		if os.matchTTLValueAdvanced(ttlStr, result.TTL) {
			score += 25
		}
	}

	// 窗口大小检查
	if winStr, exists := testData["W"]; exists {
		maxScore += 20
		if os.matchWindowValueAdvanced(winStr, result.WindowSize) {
			score += 20
		}
	}

	// DF位检查
	if dfStr, exists := testData["DF"]; exists {
		maxScore += 15
		df := (result.IPFlags & 0x4000) != 0
		if os.matchDFValue(dfStr, df) {
			score += 15
		}
	}

	// TCP标志检查
	if flagStr, exists := testData["F"]; exists {
		maxScore += 10
		if os.matchFlagsValueAdvanced(flagStr, result.TCPFlags) {
			score += 10
		}
	}

	return score, maxScore
}

// getOSCategory 获取OS类别
func (os *OSScanner) getOSCategory(osName string) string {
	osName = strings.ToLower(osName)
	if strings.Contains(osName, "linux") || strings.Contains(osName, "ubuntu") ||
		strings.Contains(osName, "debian") || strings.Contains(osName, "redhat") ||
		strings.Contains(osName, "centos") || strings.Contains(osName, "fedora") {
		return "Linux"
	} else if strings.Contains(osName, "windows") || strings.Contains(osName, "microsoft") {
		return "Windows"
	} else if strings.Contains(osName, "freebsd") || strings.Contains(osName, "openbsd") ||
		strings.Contains(osName, "netbsd") || strings.Contains(osName, "darwin") ||
		strings.Contains(osName, "macos") || strings.Contains(osName, "mac os") {
		return "Unix"
	} else if strings.Contains(osName, "cisco") || strings.Contains(osName, "juniper") ||
		strings.Contains(osName, "router") || strings.Contains(osName, "switch") {
		return "Network"
	}
	return "Other"
}

// performAdvancedGenericMatching 执行高级通用匹配
func (os *OSScanner) performAdvancedGenericMatching(results map[string]*ProbeResult) string {
	// 收集所有特征
	features := os.analyzeOSFeatures(results)

	fmt.Printf("[DEBUG] OS Features: TTL=%d, DF=%t, WinSize=%d, TCPFlags=0x%02x, ResponseCount=%d\n",
		features.avgTTL, features.dfSet, features.avgWindowSize, features.commonFlags, features.responseCount)

	// 基于特征评分
	linuxScore := os.calculateLinuxScore(features)
	windowsScore := os.calculateWindowsScore(features)
	unixScore := os.calculateUnixScore(features)

	fmt.Printf("[DEBUG] Advanced scoring - Linux: %d, Windows: %d, Unix: %d\n",
		linuxScore, windowsScore, unixScore)

	// 选择最高分
	if linuxScore > windowsScore && linuxScore > unixScore && linuxScore >= 50 {
		if features.avgTTL >= 60 && features.avgTTL <= 68 {
			return "Linux 5.4 - 6.X (Ubuntu 20.04 - 22.04)"
		}
		return "Linux 2.6.X - 6.X"
	} else if windowsScore > linuxScore && windowsScore > unixScore && windowsScore >= 45 {
		return "Microsoft Windows"
	} else if unixScore > linuxScore && unixScore > windowsScore && unixScore >= 40 {
		return "Unix/BSD"
	}

	return ""
}

// OSFeatures OS特征结构
type OSFeatures struct {
	avgTTL        int
	dfSet         bool
	avgWindowSize int
	commonFlags   uint8
	responseCount int
	hasICMP       bool
	hasTCP        bool
	hasUDP        bool
}

// analyzeOSFeatures 分析OS特征
func (os *OSScanner) analyzeOSFeatures(results map[string]*ProbeResult) *OSFeatures {
	features := &OSFeatures{}

	ttlSum := 0
	winSum := 0
	validResponses := 0
	dfCount := 0
	flagsMap := make(map[uint8]int)

	for probeType, result := range results {
		if !result.Received {
			continue
		}

		validResponses++
		ttlSum += int(result.TTL)
		winSum += int(result.WindowSize)

		if (result.IPFlags & 0x4000) != 0 {
			dfCount++
		}

		flagsMap[result.TCPFlags]++

		// 探测类型统计
		if probeType == "IE" {
			features.hasICMP = true
		} else if probeType == "U1" {
			features.hasUDP = true
		} else {
			features.hasTCP = true
		}
	}

	if validResponses > 0 {
		features.avgTTL = ttlSum / validResponses
		features.avgWindowSize = winSum / validResponses
		features.dfSet = dfCount > validResponses/2
		features.responseCount = validResponses

		// 找最常见的TCP标志
		maxCount := 0
		for flags, count := range flagsMap {
			if count > maxCount {
				maxCount = count
				features.commonFlags = flags
			}
		}
	}

	return features
}

// calculateLinuxScore 计算Linux分数
func (os *OSScanner) calculateLinuxScore(features *OSFeatures) int {
	score := 0

	// TTL特征 (Linux默认64)
	if features.avgTTL >= 59 && features.avgTTL <= 69 {
		score += 40
	} else if features.avgTTL >= 54 && features.avgTTL <= 74 {
		score += 25 // 考虑网络跳数
	}

	// DF位通常设置
	if features.dfSet {
		score += 20
	}

	// 窗口大小特征
	if features.avgWindowSize >= 5760 || features.avgWindowSize == 0 {
		score += 15
	}

	// 响应行为
	if features.responseCount >= 3 {
		score += 10
	}

	// ICMP响应 (Linux通常响应)
	if features.hasICMP {
		score += 5
	}

	return score
}

// calculateWindowsScore 计算Windows分数
func (os *OSScanner) calculateWindowsScore(features *OSFeatures) int {
	score := 0

	// TTL特征 (Windows默认128)
	if features.avgTTL >= 123 && features.avgTTL <= 133 {
		score += 40
	} else if features.avgTTL >= 118 && features.avgTTL <= 138 {
		score += 25
	}

	// 窗口大小特征
	if features.avgWindowSize == 8192 || features.avgWindowSize == 16384 ||
		features.avgWindowSize == 65535 || features.avgWindowSize == 64240 {
		score += 20
	}

	// DF位行为 (较新Windows设置，较老不设置)
	if features.dfSet {
		score += 10 // 较低权重
	}

	// 响应行为
	if features.responseCount >= 3 {
		score += 10
	}

	return score
}

// calculateUnixScore 计算Unix分数
func (os *OSScanner) calculateUnixScore(features *OSFeatures) int {
	score := 0

	// TTL特征 (BSD/Unix通常255或64)
	if features.avgTTL >= 250 && features.avgTTL <= 255 {
		score += 35
	} else if features.avgTTL >= 59 && features.avgTTL <= 69 {
		score += 20 // 某些Unix也用64
	}

	// 窗口大小特征
	if features.avgWindowSize == 32768 || features.avgWindowSize == 65535 {
		score += 15
	}

	// 响应行为
	if features.responseCount >= 2 {
		score += 10
	}

	return score
}

// selectBestMatch 智能选择最佳匹配
func (os *OSScanner) selectBestMatch(matches []MatchResult, results map[string]*ProbeResult, quickGuess string) MatchResult {
	if len(matches) == 0 {
		return MatchResult{Name: "Unknown", Confidence: 0}
	}

	bestMatch := matches[0]

	// 如果最高匹配置信度很低，考虑快速分类结果
	if bestMatch.Confidence < 40 && quickGuess != "" {
		// 寻找匹配快速分类的结果
		for _, match := range matches {
			if strings.Contains(strings.ToLower(match.Name), strings.ToLower(quickGuess)) {
				if match.Confidence >= 20 { // 最小阈值
					fmt.Printf("[DEBUG] Using quick classification guided result: %s\n", match.Name)
					return match
				}
			}
		}
	}

	// 检查是否有明显的Linux系统但被错误分类
	if quickGuess == "Linux" && bestMatch.Category != "Linux" {
		for _, match := range matches {
			if match.Category == "Linux" && match.Confidence >= 25 {
				fmt.Printf("[DEBUG] Correcting to Linux system: %s\n", match.Name)
				return match
			}
		}
	}

	return bestMatch
}

// matchTTLValue 匹配TTL值
func (os *OSScanner) matchTTLValue(ttlStr string, actualTTL uint8) bool {
	// 解析TTL范围，如 "3B-45"
	if strings.Contains(ttlStr, "-") {
		parts := strings.Split(ttlStr, "-")
		if len(parts) == 2 {
			// 十六进制范围
			low, err1 := os.parseHex(parts[0])
			high, err2 := os.parseHex(parts[1])
			if err1 == nil && err2 == nil {
				return actualTTL >= uint8(low) && actualTTL <= uint8(high)
			}
		}
	}

	// 单个值
	if val, err := os.parseHex(ttlStr); err == nil {
		return actualTTL == uint8(val)
	}

	// 常见TTL值检查
	commonTTLs := map[string]uint8{
		"40": 64,  // Linux默认
		"80": 128, // Windows默认
		"FF": 255, // 某些系统
	}

	if expectedTTL, exists := commonTTLs[strings.ToUpper(ttlStr)]; exists {
		// 允许10的误差（网络跳数）
		return actualTTL >= expectedTTL-10 && actualTTL <= expectedTTL
	}

	return false
}

// matchWindowValue 匹配窗口大小值
func (os *OSScanner) matchWindowValue(winStr string, actualWin uint16) bool {
	// 解析窗口大小，如 "16A0", "8000"
	if val, err := os.parseHex(winStr); err == nil {
		return actualWin == uint16(val)
	}

	// 范围匹配
	if strings.Contains(winStr, "-") {
		parts := strings.Split(winStr, "-")
		if len(parts) == 2 {
			low, err1 := os.parseHex(parts[0])
			high, err2 := os.parseHex(parts[1])
			if err1 == nil && err2 == nil {
				return actualWin >= uint16(low) && actualWin <= uint16(high)
			}
		}
	}

	return false
}

// matchDFValue 匹配DF位值
func (os *OSScanner) matchDFValue(dfStr string, actualDF bool) bool {
	switch strings.ToUpper(dfStr) {
	case "Y":
		return actualDF
	case "N":
		return !actualDF
	case "S": // Sometimes
		return true // 允许任何值
	}
	return false
}

// matchResponseValue 匹配响应值
func (os *OSScanner) matchResponseValue(respStr string, actualResp bool) bool {
	switch strings.ToUpper(respStr) {
	case "Y":
		return actualResp
	case "N":
		return !actualResp
	case "S": // Sometimes
		return true // 允许任何值
	}
	return false
}

// matchFlagsValue 匹配TCP标志位值
func (os *OSScanner) matchFlagsValue(flagStr string, actualFlags uint8) bool {
	// 解析标志位字符串，如 "AS", "AR", "R", "S+"
	expectedFlags := uint8(0)

	// 解析各种标志位组合
	if strings.Contains(flagStr, "S") {
		expectedFlags |= 0x02 // SYN
	}
	if strings.Contains(flagStr, "A") {
		expectedFlags |= 0x10 // ACK
	}
	if strings.Contains(flagStr, "R") {
		expectedFlags |= 0x04 // RST
	}
	if strings.Contains(flagStr, "F") {
		expectedFlags |= 0x01 // FIN
	}
	if strings.Contains(flagStr, "P") {
		expectedFlags |= 0x08 // PSH
	}
	if strings.Contains(flagStr, "U") {
		expectedFlags |= 0x20 // URG
	}

	// 特殊情况处理
	if flagStr == "0" {
		return actualFlags == 0
	}

	if strings.Contains(flagStr, "+") {
		// 至少包含指定标志位
		return (actualFlags & expectedFlags) == expectedFlags
	}

	// 精确匹配
	return actualFlags == expectedFlags
}

// parseHex 解析十六进制字符串
func (os *OSScanner) parseHex(hexStr string) (int, error) {
	// 移除可能的前缀
	hexStr = strings.TrimPrefix(hexStr, "0x")
	hexStr = strings.TrimPrefix(hexStr, "0X")

	// 解析十六进制
	val := 0
	for _, char := range strings.ToUpper(hexStr) {
		val *= 16
		if char >= '0' && char <= '9' {
			val += int(char - '0')
		} else if char >= 'A' && char <= 'F' {
			val += int(char - 'A' + 10)
		} else {
			return 0, fmt.Errorf("invalid hex character: %c", char)
		}
	}

	return val, nil
}

// performGenericMatching 执行通用匹配
func (os *OSScanner) performGenericMatching(results map[string]*ProbeResult) string {
	// 基于常见特征进行通用OS识别
	linuxScore := 0
	windowsScore := 0
	macScore := 0

	receivedCount := 0
	for _, result := range results {
		if !result.Received {
			continue
		}
		receivedCount++

		// Linux特征检查 (Ubuntu/Debian/CentOS等)
		// 1. TTL通常是64左右
		if result.TTL >= 54 && result.TTL <= 74 {
			linuxScore += 25
		}
		// 2. 窗口大小通常较大且多样
		if result.WindowSize >= 5760 {
			linuxScore += 20
		}
		// 3. DF位通常设置
		if (result.IPFlags & 0x4000) != 0 {
			linuxScore += 15
		}
		// 4. Linux常见窗口大小
		if result.WindowSize == 5840 || result.WindowSize == 29200 ||
			result.WindowSize == 14600 || result.WindowSize == 65535 {
			linuxScore += 20
		}

		// Windows特征检查
		// 1. TTL通常是128左右
		if result.TTL >= 118 && result.TTL <= 138 {
			windowsScore += 25
		}
		// 2. 特定的窗口大小
		if result.WindowSize == 8192 || result.WindowSize == 16384 ||
			result.WindowSize == 65535 || result.WindowSize == 64240 {
			windowsScore += 20
		}
		// 3. Windows通常不设置DF位（较老版本）
		if (result.IPFlags & 0x4000) == 0 {
			windowsScore += 10
		}

		// macOS特征检查
		// 1. TTL通常是64
		if result.TTL >= 60 && result.TTL <= 68 {
			macScore += 15
		}
		// 2. 特定窗口大小
		if result.WindowSize == 65535 || result.WindowSize == 32768 {
			macScore += 15
		}
	}

	// 如果收到的响应太少，降低置信度
	if receivedCount < 3 {
		linuxScore /= 2
		windowsScore /= 2
		macScore /= 2
	}

	fmt.Printf("[DEBUG] Generic matching scores - Linux: %d, Windows: %d, macOS: %d (responses: %d)\n",
		linuxScore, windowsScore, macScore, receivedCount)

	// 判断最可能的OS
	if linuxScore > windowsScore && linuxScore > macScore && linuxScore >= 40 {
		// 进一步细分Linux发行版
		return "Linux 2.6.X - 6.X (likely Ubuntu/Debian)"
	} else if windowsScore > linuxScore && windowsScore > macScore && windowsScore >= 35 {
		return "Microsoft Windows (Vista/7/8/10/11)"
	} else if macScore > linuxScore && macScore > windowsScore && macScore >= 30 {
		return "Apple macOS"
	} else if linuxScore >= 25 {
		return "Linux (Unknown distribution)"
	}

	return ""
}

// matchTTLValueAdvanced 高级TTL值匹配
func (os *OSScanner) matchTTLValueAdvanced(ttlStr string, actualTTL uint8) bool {
	// 首先尝试原有的匹配方法
	if os.matchTTLValue(ttlStr, actualTTL) {
		return true
	}

	// 增加更宽松的匹配 (考虑网络跳数)
	if strings.Contains(ttlStr, "-") {
		parts := strings.Split(ttlStr, "-")
		if len(parts) == 2 {
			low, err1 := os.parseHex(parts[0])
			high, err2 := os.parseHex(parts[1])
			if err1 == nil && err2 == nil {
				// 允许更大的TTL偏差
				return actualTTL >= uint8(low-15) && actualTTL <= uint8(high+5)
			}
		}
	}

	return false
}

// matchWindowValueAdvanced 高级窗口大小匹配
func (os *OSScanner) matchWindowValueAdvanced(winStr string, actualWin uint16) bool {
	// 首先尝试原有匹配
	if os.matchWindowValue(winStr, actualWin) {
		return true
	}

	// 对于0值给予特殊处理
	if actualWin == 0 && (winStr == "0" || winStr == "0000") {
		return true
	}

	// 十六进制值的近似匹配
	if val, err := os.parseHex(winStr); err == nil {
		expectedWin := uint16(val)
		diff := int(actualWin) - int(expectedWin)
		if diff < 0 {
			diff = -diff
		}
		// 允许小的窗口大小差异
		return diff <= 100
	}

	return false
}

// matchFlagsValueAdvanced 高级标志位匹配
func (os *OSScanner) matchFlagsValueAdvanced(flagStr string, actualFlags uint8) bool {
	// 首先尝试原有匹配
	if os.matchFlagsValue(flagStr, actualFlags) {
		return true
	}

	// 对于复杂的标志组合，提供更灵活的匹配
	if flagStr == "0" || flagStr == "00" {
		return actualFlags == 0
	}

	// 如果包含+号，匹配所有指定标志位
	if strings.Contains(flagStr, "+") {
		expectedFlags := uint8(0)
		if strings.Contains(flagStr, "S") {
			expectedFlags |= 0x02
		}
		if strings.Contains(flagStr, "A") {
			expectedFlags |= 0x10
		}
		if strings.Contains(flagStr, "R") {
			expectedFlags |= 0x04
		}
		return (actualFlags & expectedFlags) == expectedFlags
	}

	return false
}
