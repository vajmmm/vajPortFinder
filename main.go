package main

import (
	"fmt"
	"os"
	"portfinder/scanner"
	"portfinder/util"
	"portfinder/vars"

	"runtime"
)

func main() {
	if len(os.Args) == 4 {
		ipList := os.Args[1]
		portList := os.Args[2]
		mode := os.Args[3]
		ips, _ := util.GetIpList(ipList)

		ports, _, portCount := util.GetPorts(portList)

		task, _ := util.GenerateTask(ips, ports)

		var scanImpl scanner.Scanner
		switch mode {
		case "full":
			//scanImpl = &scanner.FullConnectScanner{}
			scanImpl = scanner.NewFullConnectScanner()
			scanner.AssigningTasks(task, scanImpl)
		case "syn":
			scanner.StartSynListener()
			scanImpl = scanner.NewsynScanner()
			scanner.AssigningTasks(task, scanImpl)
		case "udp":
			scanImpl = scanner.NewUDPScanner()
			scanner.AssigningTasks(task, scanImpl)
		case "fin":
			scanner.StartFINListener()
			scanImpl = scanner.NewFINScanner()
			scanner.AssigningTasks(task, scanImpl)
		case "fin-advanced":
			scanner.StartFINListener()
			scanImpl = scanner.NewFINScannerAdvanced(true)
			scanner.AssigningTasks(task, scanImpl)

		case "ack":
			scanner.StartACKListener()
			scanImpl = scanner.NewACKScanner()
			scanner.AssigningTasks(task, scanImpl)

			totalPorts := 0
			vars.Result.Range(func(key, value interface{}) bool {
				if ports, ok := value.([]int); ok {
					totalPorts += len(ports)
				}
				return true
			})
			fmt.Println("存储的端口总数:", totalPorts)

			if portCount == totalPorts {
				fmt.Println("All the %d ports is unfiltered!!!", totalPorts)
			}
			return
		default:
			fmt.Println("未知扫描模式:", mode)
			return
		}
		util.PrintResult()
		return
	} else {
		fmt.Printf("Usage: %v <iplist> <portlist> <mode>\n", os.Args[0])
		fmt.Println("mode: full (full connect scan), syn (syn scan), udp (udp scan), fin (fin scan), fin-advanced (advanced fin scan)")
		return
	}

}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
