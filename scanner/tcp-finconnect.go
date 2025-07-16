package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"portfinder/util"
	"sync"
	"syscall"
	"time"
)

var (
	finResponseMap  = make(map[FINResponseKey]chan bool)
	finResponseLock sync.Mutex
)

type FINResponseKey struct {
	DstIP   string
	DstPort uint16
	SrcPort uint16
}

type finScanner struct{}

func NewFINScanner() *finScanner {
	return &finScanner{}
}

func (s *finScanner) Connect(id int, ip string, port int) error {
	srcIP, srcPort, err := util.LocalIPPort(net.ParseIP(ip))
	if err != nil {
		return err
	}

	dstIP := net.ParseIP(ip).To4()
	if dstIP == nil {
		return fmt.Errorf("invalid destination IP address : %v", ip)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("failed to create socket: %v", err)
	}
	defer syscall.Close(fd)

	packet := buildFINPacket(srcIP, dstIP, uint16(srcPort), uint16(port))

	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], dstIP)

	key := FINResponseKey{
		DstIP:   dstIP.String(),
		DstPort: uint16(port),
		SrcPort: uint16(srcPort),
	}

	ch := make(chan bool, 1)
	finResponseLock.Lock()
	finResponseMap[key] = ch
	finResponseLock.Unlock()
	defer func() {
		finResponseLock.Lock()
		delete(finResponseMap, key)
		finResponseLock.Unlock()
	}()

	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		return fmt.Errorf("failed to send FIN packet: %v", err)
	}

	select {
	case open := <-ch:
		if open {
			fmt.Printf("[+] Port %d is open on %s\n", port, ip)
		} else {
			return fmt.Errorf("port %d is closed on %s", port, ip)
		}

	case <-time.After(1 * time.Second):
		// FIN扫描中，超时通常表示端口开放或被过滤
		fmt.Printf("[+] Port %d timeout (likely open/filtered) on %s\n", port, ip)
	}

	return nil
}

func StartFINListener() {
	recvFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		panic("FIN listener failed to create socket")
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := syscall.Recvfrom(recvFD, buf, 0)
			if err != nil || n < 40 {
				continue
			}

			ipHeaderLen := int(buf[0]&0x0f) * 4
			tcp := buf[ipHeaderLen:]

			dstPort := binary.BigEndian.Uint16(tcp[0:2]) // 返回包报文发送方，即被扫描端口
			srcPort := binary.BigEndian.Uint16(tcp[2:4]) // 返回包接收方，即本机端口
			flags := tcp[13]

			dstIP := fmt.Sprintf("%d.%d.%d.%d", buf[12], buf[13], buf[14], buf[15])

			key := FINResponseKey{
				DstIP:   dstIP,
				DstPort: dstPort,
				SrcPort: srcPort,
			}

			finResponseLock.Lock()
			ch, ok := finResponseMap[key]
			finResponseLock.Unlock()

			if ok {
				if (flags & 0x04) == 0x04 { // RST - 端口关闭
					select {
					case ch <- false:
					default:
					}
				} else if (flags & 0x12) == 0x12 { // SYN+ACK - 不应该收到，但表示端口开放
					select {
					case ch <- true:
					default:
					}
				}
				// FIN扫描中，无响应通常表示端口开放或被过滤
			}
		}
	}()
}

func buildFINPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	tcpHeader := make([]byte, 20)

	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort) // 源端口
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort) // 目的端口
	binary.BigEndian.PutUint32(tcpHeader[4:8], 0)       // 序列号（初始为0）
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)      // 确认号（初始为0）

	tcpHeader[12] = 5 << 4                               // 数据偏移（Data Offset）和保留位（Reserved）。
	tcpHeader[13] = 1                                    // Flags，设置FIN标志位 (0x01)
	binary.BigEndian.PutUint16(tcpHeader[14:16], 0x7210) // 窗口大小（Window Size）
	tcpHeader[16] = 0                                    // 校验和和紧急指针
	tcpHeader[17] = 0                                    // 校验和和紧急指针
	tcpHeader[18] = 0
	tcpHeader[19] = 0 // 选项和填充

	psHeader := []byte{}
	psHeader = append(psHeader, srcIP...)
	psHeader = append(psHeader, dstIP...)
	psHeader = append(psHeader, 0)
	psHeader = append(psHeader, syscall.IPPROTO_TCP)
	psHeader = append(psHeader, byte(len(tcpHeader)>>8), byte(len(tcpHeader)))

	cs := checksum(append(psHeader, tcpHeader...))
	binary.BigEndian.PutUint16(tcpHeader[16:18], cs) // 设置校验和

	return tcpHeader
}

// FINScannerAdvanced 高级FIN扫描器，支持更多TCP标志位组合
type FINScannerAdvanced struct {
	flags uint8 // 自定义TCP标志位
}

func NewFINScannerAdvanced(randomizeSourcePort bool) *FINScannerAdvanced {
	return &FINScannerAdvanced{
		flags: 0x01, // 默认FIN标志
	}
}

func (s *FINScannerAdvanced) Connect(id int, ip string, port int) error {
	srcIP, srcPort, err := util.LocalIPPort(net.ParseIP(ip))
	if err != nil {
		return err
	}

	dstIP := net.ParseIP(ip).To4()
	if dstIP == nil {
		return fmt.Errorf("invalid destination IP address : %v", ip)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("failed to create socket: %v", err)
	}
	defer syscall.Close(fd)

	packet := s.buildAdvancedFINPacket(srcIP, dstIP, uint16(srcPort), uint16(port))

	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], dstIP)

	key := FINResponseKey{
		DstIP:   dstIP.String(),
		DstPort: uint16(port),
		SrcPort: uint16(srcPort),
	}

	ch := make(chan bool, 1)
	finResponseLock.Lock()
	finResponseMap[key] = ch
	finResponseLock.Unlock()
	defer func() {
		finResponseLock.Lock()
		delete(finResponseMap, key)
		finResponseLock.Unlock()
	}()

	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		return fmt.Errorf("failed to send advanced FIN packet: %v", err)
	}

	select {
	case open := <-ch:
		if open {
			fmt.Printf("[+] Port %d is open on %s (advanced FIN)\n", port, ip)
		} else {
			return fmt.Errorf("port %d is closed on %s", port, ip)
		}

	case <-time.After(1 * time.Second):
		fmt.Printf("[+] Port %d timeout (likely open/filtered) on %s (advanced FIN)\n", port, ip)
	}

	return nil
}

// SetCustomFlags 设置自定义TCP标志
func (s *FINScannerAdvanced) SetCustomFlags(flags uint8) {
	s.flags = flags
}

func (s *FINScannerAdvanced) buildAdvancedFINPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	tcpHeader := make([]byte, 20)

	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort) // 源端口
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort) // 目的端口
	binary.BigEndian.PutUint32(tcpHeader[4:8], 0)       // 序列号（初始为0）
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)      // 确认号（初始为0）

	tcpHeader[12] = 5 << 4                               // 数据偏移（Data Offset）和保留位（Reserved）。
	tcpHeader[13] = s.flags                              // 使用自定义标志位
	binary.BigEndian.PutUint16(tcpHeader[14:16], 0x7210) // 窗口大小（Window Size）
	tcpHeader[16] = 0                                    // 校验和和紧急指针
	tcpHeader[17] = 0                                    // 校验和和紧急指针
	tcpHeader[18] = 0
	tcpHeader[19] = 0 // 选项和填充

	psHeader := []byte{}
	psHeader = append(psHeader, srcIP...)
	psHeader = append(psHeader, dstIP...)
	psHeader = append(psHeader, 0)
	psHeader = append(psHeader, syscall.IPPROTO_TCP)
	psHeader = append(psHeader, byte(len(tcpHeader)>>8), byte(len(tcpHeader)))

	cs := checksum(append(psHeader, tcpHeader...))
	binary.BigEndian.PutUint16(tcpHeader[16:18], cs) // 设置校验和

	return tcpHeader
}
