package main

import (
	"fmt"
	"os"
	"portfinder/scanner"
	"portfinder/util"

	"runtime"
)

func main() {
	if len(os.Args) == 4 {
		ipList := os.Args[1]
		portList := os.Args[2]
		mode := os.Args[3]
		ips, _ := util.GetIpList(ipList)

		ports, _ := util.GetPorts(portList)

		task, _ := util.GenerateTask(ips, ports)

		var scanImpl scanner.Scanner
		switch mode {
		case "full":
			//scanImpl = &scanner.FullConnectScanner{}
			scanImpl = scanner.NewFullConnectScanner()
			scanner.AssigningTasks(task, scanImpl)
		case "syn":
			scanner.StartGlobalListener()
			scanImpl = scanner.NewsynScanner()
			scanner.AssigningTasks(task, scanImpl)
		default:
			fmt.Println("未知扫描模式:", mode)
			return
		}
		util.PrintResult()
		return
	} else {
		fmt.Printf("Usage: %v <iplist> <portlist> <mode>\n", os.Args[0])
		fmt.Println("mode: full (full connect scan) or syn (syn scan, not implemented yet)")
		return
	}

}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
