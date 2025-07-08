package util

import (
	"fmt"
	"net"
	"portfinder/vars"
	"strconv"
	"strings"

	"github.com/malfunkt/iprange"
)

func GetIpList(ips string) ([]net.IP, error) {
	addressList, err := iprange.ParseList(ips)
	if err != nil {
		return nil, err
	}
	list := addressList.Expand()
	return list, err
}

func GetPorts(selection string) ([]int, error) {
	ports := []int{}
	if selection == "" {
		return ports, nil
	}
	ranges := strings.Split(selection, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")

			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port selection segment: '%s'", r)
			}

			p1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port number :'%s'", parts[0])
			}

			p2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port number :'%s'", parts[1])
			}

			if p1 > p2 {
				return nil, fmt.Errorf("invalid port range:%d-%d", p1, p2)
			}

			for i := p1; i <= p2; i++ {
				ports = append(ports, i)
			}

		} else {
			if port, err := strconv.Atoi(r); err != nil {
				return nil, fmt.Errorf("nvalid port number :'%s'", r)
			} else {
				ports = append(ports, port)
			}
		}

	}
	return ports, nil
}

func GenerateTask(ipList []net.IP, ports []int) ([]map[string]int, int) {
	tasks := make([]map[string]int, 0)

	for _, ip := range ipList {
		for _, port := range ports {
			ipPort := map[string]int{ip.String(): port}
			tasks = append(tasks, ipPort)

		}
	}
	//fmt.Println("tasks映射内容为:", tasks)
	return tasks, len(tasks)
}

func LocalIPPort(dstIP net.IP) (net.IP, int, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstIP.String()+":234")
	//fmt.Println("serverAddr=", serverAddr, "  err=", err)
	if err != nil {
		return nil, 0, err
	}

	if conn, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		//fmt.Println("con=", conn, "  err=", err)
		if udpaddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			//fmt.Println("udpaddr=", udpaddr, "  err=", err)
			return udpaddr.IP, udpaddr.Port, nil
		}
	}
	return nil, -1, err
}

func PrintResult() {
	vars.Result.Range(func(key, value interface{}) bool {
		fmt.Printf("ip:%v\n", key)
		fmt.Printf("ports: %v\n", value)
		fmt.Println(strings.Repeat("-", 50))
		return true
	})
}

func SaveResult(ip string, port int, err error) error {
	v, ok := vars.Result.Load(ip)
	if ok {
		if ports, ok1 := v.([]int); ok1 {
			ports = append(ports, port)
			vars.Result.Store(ip, ports)
		}
	} else {
		vars.Result.Store(ip, []int{port})
	}
	return err
}
