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
	responseMap  = make(map[SYNResponseKey]chan bool)
	responseLock sync.Mutex
)

type SYNResponseKey struct {
	DstIP   string
	DstPort uint16
	SrcPort uint16
}

type synScanner struct{}

func NewsynScanner() *synScanner {
	return &synScanner{}
}

func (s *synScanner) Connect(id int, ip string, port int) error {

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
	/*
		syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
		err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "enp0s3")
		if err != nil {
			fmt.Printf("绑定网卡失败: %v\n", err)
			return err
		}
	*/
	//fmt.Println("绑定网卡成功")
	//packet := buildIPTCPPacket(srcIP, dstIP, uint16(srcPort), uint16(port))
	packet := buildSYNPacket(srcIP, dstIP, uint16(srcPort), uint16(port))

	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], dstIP)
	//fmt.Printf("addr.Port = %d\n", addr.Port)
	//fmt.Printf("addr.Addr = %v\n", addr.Addr) // [4]byte 类型
	//fmt.Printf("addr.Addr as IP = %v\n", net.IP(addr.Addr[:]).String())

	key := SYNResponseKey{
		DstIP:   dstIP.String(),
		DstPort: uint16(port),
		SrcPort: uint16(srcPort),
	}

	ch := make(chan bool, 1)
	responseLock.Lock()
	responseMap[key] = ch
	responseLock.Unlock()
	defer func() {
		responseLock.Lock()
		delete(responseMap, key)
		responseLock.Unlock()
	}()

	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		return fmt.Errorf("failed to send SYN packet: %v", err)
	}

	select {
	case open := <-ch:
		if open {
			fmt.Printf("[+] Port %d is open on %s\n", port, ip)
		} else {
			//fmt.Printf("[-] Port %d is closed on %s\n", port, ip)
			return fmt.Errorf("port %d is closed on %s", port, ip)
		}

	case <-time.After(1 * time.Second):
		fmt.Printf("[-] Timeout: %s:%d\n", ip, port)
	}

	return nil
}

func StartSynListener() {
	recvFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		panic("Global listener failed to create socket")
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

			dstPort := binary.BigEndian.Uint16(tcp[0:2]) //返回包报文发送方，即被扫描端口
			srcPort := binary.BigEndian.Uint16(tcp[2:4]) //返回包接收方，即本机端口
			flags := tcp[13]

			dstIP := fmt.Sprintf("%d.%d.%d.%d", buf[12], buf[13], buf[14], buf[15])

			key := SYNResponseKey{
				DstIP:   dstIP,
				DstPort: dstPort,
				SrcPort: srcPort,
			}
			/*
				responseLock.Lock()

				fmt.Println("=== Current ResponseKeys in responseMap ===")
				for key := range responseMap {
					fmt.Printf("DstIP: %s, DstPort: %d, SrcPort: %d\n", key.DstIP, key.DstPort, key.SrcPort)
				}
				println(key.DstIP, key.DstPort, key.SrcPort)
				fmt.Println("==========================================")
				responseLock.Unlock()
			*/
			fmt.Println(flags)
			responseLock.Lock()
			ch, ok := responseMap[key]
			responseLock.Unlock()
			//println(ok)
			if ok {
				if (flags & 0x12) == 0x12 { // SYN+ACK
					select {
					case ch <- true:
					default:
					}
				} else if (flags & 0x04) == 0x04 { // RST
					select {
					case ch <- false:
					default:
					}
				}
			}
		}
	}()
}

func buildSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	tcpHeader := make([]byte, 20)

	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort) // 源端口
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort) // 目的端口
	binary.BigEndian.PutUint32(tcpHeader[4:8], 0)       // 序列号（初始为0）
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)      // 确认号（初始为0）

	tcpHeader[12] = 5 << 4                               //数据偏移（Data Offset）和保留位（Reserved）。
	tcpHeader[13] = 2                                    // Flags，设置SYN标志位
	binary.BigEndian.PutUint16(tcpHeader[14:16], 0x7210) //窗口大小（Window Size）
	tcpHeader[16] = 0                                    //校验和和紧急指针
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
	//fmt.Printf("SYN packet: srcIP=%s, dstIP=%s, srcPort=%d, dstPort=%d, checksum=0x%x\n",srcIP, dstIP, srcPort, dstPort, cs)
	return tcpHeader
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

/*
func StartGlobalListener() {
	// ETH_P_IP 网络层协议，用于抓 IPv4 包，注意字节序转换 htons
	const ETH_P_IP = 0x0800
	htons := func(i uint16) uint16 {
		return (i<<8)&0xff00 | i>>8
	}

	recvFD, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ETH_P_IP)))
	if err != nil {
		panic("Global listener failed to create AF_PACKET socket: " + err.Error())
	}

	// 获取指定网卡信息（如 enp0s3）
	ifaceName := "enp0s3"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		panic("Failed to find interface " + ifaceName + ": " + err.Error())
	}

	// 构造 SockaddrLinklayer 并绑定 socket 到该网卡
	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(ETH_P_IP),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(recvFD, sll); err != nil {
		panic("Failed to bind socket to interface " + ifaceName + ": " + err.Error())
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := syscall.Recvfrom(recvFD, buf, 0)
			if err != nil || n < 54 { // 14字节以太网头 + 20字节IP头 + 20字节TCP头最小长度
				continue
			}

			lladdr, ok := from.(*syscall.SockaddrLinklayer)
			if !ok {
				continue
			}

			// 根据接口索引获取网卡名称
			iface, err := net.InterfaceByIndex(lladdr.Ifindex)
			if err != nil {
				fmt.Println("Interface lookup failed:", err)
				continue
			}
			fmt.Printf("Received packet from interface %s (index %d)\n", iface.Name, iface.Index)
			ipStart := 14
			ipHeader := buf[ipStart : ipStart+20]

			ipHeaderLen := int(ipHeader[0]&0x0f) * 4
			if ipHeaderLen < 20 {
				continue
			}

			tcpStart := ipStart + ipHeaderLen
			if tcpStart+20 > n {
				continue
			}

			tcpHeader := buf[tcpStart : tcpStart+20]

			dstPort := binary.BigEndian.Uint16(tcpHeader[0:2]) // 返回包发送方端口（被扫描端口）
			srcPort := binary.BigEndian.Uint16(tcpHeader[2:4]) // 返回包接收方端口（本机端口）
			flags := tcpHeader[13]

			dstIP := fmt.Sprintf("%d.%d.%d.%d", ipHeader[12], ipHeader[13], ipHeader[14], ipHeader[15])
			println(dstIP)
			key := ResponseKey{
				DstIP:   dstIP,
				DstPort: dstPort,
				SrcPort: srcPort,
			}

			fmt.Printf("Packet from iface %s (index %d), dstIP: %s, dstPort: %d, srcPort: %d, flags: 0x%x\n",
				iface.Name, iface.Index, dstIP, dstPort, srcPort, flags)

			responseLock.Lock()
			ch, ok := responseMap[key]
			responseLock.Unlock()

			if ok {
				if (flags & 0x12) == 0x12 { // SYN+ACK
					select {
					case ch <- true:
					default:
					}
				} else if (flags & 0x04) == 0x04 { // RST
					select {
					case ch <- false:
					default:
					}
				}
			}
		}
	}()
}
*/

/*
	func buildIPTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
		ipHeader := make([]byte, 20)
		ipHeader[0] = 0x45
		ipHeader[1] = 0x00
		totalLen := 40
		binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
		ipHeader[5] = 0x00
		ipHeader[6] = 0x40
		ipHeader[8] = 64
		ipHeader[9] = syscall.IPPROTO_TCP
		copy(ipHeader[12:16], srcIP.To4())
		copy(ipHeader[16:20], dstIP.To4())
		csIP := checksum(ipHeader)
		binary.BigEndian.PutUint16(ipHeader[10:12], csIP)

		tcpHeader := make([]byte, 20)
		binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
		binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
		binary.BigEndian.PutUint32(tcpHeader[4:8], 0)
		binary.BigEndian.PutUint32(tcpHeader[8:12], 0)
		tcpHeader[12] = 0x50
		tcpHeader[13] = 0x02
		binary.BigEndian.PutUint16(tcpHeader[14:16], 0x7210)

		psHeader := []byte{}
		psHeader = append(psHeader, srcIP.To4()...)
		psHeader = append(psHeader, dstIP.To4()...)
		psHeader = append(psHeader, 0)
		psHeader = append(psHeader, syscall.IPPROTO_TCP)
		psHeader = append(psHeader, byte(len(tcpHeader)>>8), byte(len(tcpHeader)))
		cs := checksum(append(psHeader, tcpHeader...))
		binary.BigEndian.PutUint16(tcpHeader[16:18], cs)

		return append(ipHeader, tcpHeader...)
	}
*/
