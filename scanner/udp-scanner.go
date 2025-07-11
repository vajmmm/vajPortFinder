package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// 用于标识响应通道
type UDPResponseKey struct {
	DstIP   string
	DstPort uint16
}

var (
	icmpResponseMap  = make(map[UDPResponseKey]chan bool)
	icmpResponseLock sync.Mutex
)

type UDPScanner struct{}

func NewUDPScanner() *UDPScanner {
	return &UDPScanner{}
}

// UDP发送器
func (u *UDPScanner) Connect(id int, ip string, port int) error {
	_ = id
	dstAddr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", dstAddr, 1*time.Second)
	if err != nil {
		return fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	key := UDPResponseKey{
		DstIP:   ip,
		DstPort: uint16(port),
	}

	ch := make(chan bool, 1)
	icmpResponseLock.Lock()
	icmpResponseMap[key] = ch
	icmpResponseLock.Unlock()
	defer func() {
		icmpResponseLock.Lock()
		delete(icmpResponseMap, key)
		icmpResponseLock.Unlock()
	}()

	_, err = conn.Write([]byte("ping"))
	if err != nil {
		return fmt.Errorf("send error: %v", err)
	}

	select {
	case closed := <-ch:
		if closed {
			return fmt.Errorf("port %d is closed (ICMP unreachable)", port)
		}
	case <-time.After(2 * time.Second):
		// 超时，可能是开放或被过滤
		return nil
	}

	return nil
}

// 启动监听ICMP端口不可达的协程（建议在主程序中调用一次）
func StartICMPListener() {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0800))) // IPv4
	if err != nil {
		panic("create raw socket failed: " + err.Error())
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil || n < 42 {
				continue
			}

			// IP头从第14位开始（前14是Ethernet）
			ipStart := 14
			if buf[ipStart+9] != 1 { // ICMP协议号
				continue
			}
			icmpType := buf[ipStart+20]
			icmpCode := buf[ipStart+21]
			if icmpType != 3 || (icmpCode != 3 && icmpCode != 1 && icmpCode != 2) {
				continue
			}

			// ICMP封装的原始IP + UDP头信息
			innerIP := buf[ipStart+28:]
			if len(innerIP) < 28 {
				continue
			}
			dstIP := fmt.Sprintf("%d.%d.%d.%d", innerIP[16], innerIP[17], innerIP[18], innerIP[19])
			dstPort := binary.BigEndian.Uint16(innerIP[22:24])

			key := UDPResponseKey{
				DstIP:   dstIP,
				DstPort: dstPort,
			}

			icmpResponseLock.Lock()
			ch, ok := icmpResponseMap[key]
			icmpResponseLock.Unlock()
			if ok {
				select {
				case ch <- true: // 表示目标端口不可达
				default:
				}
			}
		}
	}()
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
