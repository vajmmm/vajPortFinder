package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"portfinder/util"
	"portfinder/vars"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type ACKResponseKey struct {
	DstIP   string
	DstPort uint16
	SrcPort uint16
}

var (
	ackResponseMap  = make(map[ACKResponseKey]chan bool)
	ackResponseLock sync.Mutex
)

type ackScanner struct {
}

func NewACKScanner() *ackScanner {
	return &ackScanner{}
}

func (s *ackScanner) Connect(id int, ip string, port int) error {
	srcIP, srcPort, err := util.LocalIPPort(net.ParseIP(ip))
	if err != nil {
		return err
	}

	dstIP := net.ParseIP(ip).To4()
	if dstIP == nil {
		return fmt.Errorf("invalid destination IP")
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("socket error: %v", err)
	}
	defer syscall.Close(fd)

	packet := buildACKPacket(srcIP, dstIP, uint16(srcPort), uint16(port))

	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], dstIP)

	key := ACKResponseKey{
		DstIP:   dstIP.String(),
		DstPort: uint16(port),
		SrcPort: uint16(srcPort),
	}

	ch := make(chan bool, 1)
	ackResponseLock.Lock()
	ackResponseMap[key] = ch
	ackResponseLock.Unlock()
	defer func() {
		ackResponseLock.Lock()
		delete(ackResponseMap, key)
		ackResponseLock.Unlock()
	}()

	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		return fmt.Errorf("sendto failed: %v", err)
	}
	atomic.AddInt64(&vars.SendCounter, 1)
	select {
	case received := <-ch:
		if received {
			//fmt.Printf("[+] Port %d is unfiltered on %s\n", port, ip)

		} else {
			fmt.Println("[+] what????")
		}
	case <-time.After(3 * time.Second):
		fmt.Printf("[-] Port %d is filtered or dropped by firewall on %s\n", port, ip)
	}

	return nil
}

func StartACKListener() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		panic("ACK Listener socket creation failed: " + err.Error())
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil || n < 40 {
				continue
			}

			ipHeaderLen := int(buf[0]&0x0f) * 4
			tcp := buf[ipHeaderLen:]

			dstPort := binary.BigEndian.Uint16(tcp[0:2])
			srcPort := binary.BigEndian.Uint16(tcp[2:4])
			flags := tcp[13]

			dstIP := fmt.Sprintf("%d.%d.%d.%d", buf[12], buf[13], buf[14], buf[15])

			key := ACKResponseKey{
				DstIP:   dstIP,
				DstPort: dstPort,
				SrcPort: srcPort,
			}

			if (flags & 0x04) == 0x04 { // RST
				ackResponseLock.Lock()
				ch, ok := ackResponseMap[key]
				ackResponseLock.Unlock()
				if ok {
					select {
					case ch <- true:
					default:
					}
				}
			}
		}
	}()
}

func buildACKPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	tcpHeader := make([]byte, 20)

	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], 0)
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)
	tcpHeader[12] = 5 << 4 // header length
	tcpHeader[13] = 0x10   // ACK flag
	binary.BigEndian.PutUint16(tcpHeader[14:16], 0x7210)

	psHeader := append([]byte{}, srcIP...)
	psHeader = append(psHeader, dstIP...)
	psHeader = append(psHeader, 0)
	psHeader = append(psHeader, syscall.IPPROTO_TCP)
	psHeader = append(psHeader, byte(len(tcpHeader)>>8), byte(len(tcpHeader)))

	cs := checksum(append(psHeader, tcpHeader...))
	binary.BigEndian.PutUint16(tcpHeader[16:18], cs)
	return tcpHeader
}
