package scanner

import (
	"fmt"
	"net"
	"time"
)

type Scanner interface {
	Connect(id int, ip string, port int) error
}

type FullConnectScanner struct{}

func NewFullConnectScanner() *FullConnectScanner {
	return &FullConnectScanner{}
}

func (f *FullConnectScanner) Connect(id int, ip string, port int) error {
	_ = id
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, port), 2*time.Second)
	//print(conn)
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	if err != nil {
		return err
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		banner := string(buf[:n])
		fmt.Printf("[Banner] %s:%d -> %s\n", ip, port, banner)
	}
	return nil
}
