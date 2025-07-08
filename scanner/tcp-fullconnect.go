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
	return err
}
