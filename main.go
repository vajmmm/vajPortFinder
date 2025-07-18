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
	// 检查参数数量，支持不同的使用模式
	if len(os.Args) >= 3 {
		var ipList, portList, mode string

		// 判断参数格式
		if len(os.Args) == 3 {
			// 格式: program <iplist> <mode> (用于OS探测等不需要端口列表的模式)
			ipList = os.Args[1]
			mode = os.Args[2]
			portList = "80" // 默认端口，主要用于OS探测
		} else if len(os.Args) == 4 {
			// 格式: program <iplist> <portlist> <mode> (标准格式)
			ipList = os.Args[1]
			portList = os.Args[2]
			mode = os.Args[3]
		} else {
			printUsage()
			return
		}

		ips, _ := util.GetIpList(ipList)

		// 对于OS探测模式，端口列表不是必需的
		var ports []int
		var portCount int
		if mode != "os" {
			ports, _, portCount = util.GetPorts(portList)
		} else {
			// OS探测模式使用常用端口
			ports = []int{80} // 默认端口，实际不会用到
			portCount = 1
		}

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
			fmt.Printf("实际发包数量: %d\n", vars.SendCounter)
			if portCount == totalPorts {
				fmt.Println("All the %d ports is unfiltered!!!", totalPorts)
			}
			return
		case "os":
			// 纯OS探测模式
			fmt.Println("=== Starting Comprehensive OS Detection ===")
			for _, ip := range ips {
				ipStr := ip.String()
				fmt.Printf("\n[+] Detecting OS for %s...\n", ipStr)

				// 首先进行端口扫描找到开放端口
				scanner.StartSynListener()
				synScanner := scanner.NewsynScanner()
				commonPorts := []int{22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900}
				openPort := -1
				closedPort := 65530 // 假设这个端口是关闭的

				for _, port := range commonPorts {
					err := synScanner.Connect(0, ipStr, port)
					if err == nil {
						// 检查是否找到开放端口
						if result, ok := vars.Result.Load(ipStr); ok {
							if ports, ok := result.([]int); ok && len(ports) > 0 {
								openPort = ports[0]
								break
							}
						}
					}
				}

				if openPort == -1 {
					fmt.Printf("[-] No open ports found for %s, using port 80 as default\n", ipStr)
					openPort = 80
				} else {
					fmt.Printf("[+] Found open port %d for %s\n", openPort, ipStr)
				}

				// 执行OS探测
				osScanner := scanner.NewOSScanner(ipStr, openPort, closedPort)
				err := osScanner.LoadNmapOSDB("util/nmap-os-db.txt")
				if err != nil {
					fmt.Printf("[-] Failed to load OS database: %v\n", err)
					continue
				}

				fingerprint, err := osScanner.DoOSDetection()
				if err != nil {
					fmt.Printf("[-] OS detection failed for %s: %v\n", ipStr, err)
					continue
				}

				fmt.Printf("[+] OS Detection completed for %s:\n", ipStr)
				fmt.Printf("    OS Guess: %s\n", fingerprint.OSGuess)
				fmt.Printf("    Confidence: %d%%\n", fingerprint.Confidence)
				fmt.Printf("    Probes: %d\n", len(fingerprint.Probes))
			}
			return
		default:
			fmt.Println("未知扫描模式:", mode)
			return
		}
		util.PrintResult()
		return
	} else {
		printUsage()
		return
	}

}

// printUsage 打印使用说明
func printUsage() {
	fmt.Printf("Usage: %s <iplist> [portlist] <mode>\n", os.Args[0])
	fmt.Println("\nModes:")
	fmt.Println("  full         - Full connect scan (requires portlist)")
	fmt.Println("  syn          - SYN scan (requires portlist)")
	fmt.Println("  udp          - UDP scan (requires portlist)")
	fmt.Println("  fin          - FIN scan (requires portlist)")
	fmt.Println("  fin-advanced - Advanced FIN scan (requires portlist)")
	fmt.Println("  ack          - ACK scan (requires portlist)")
	fmt.Println("  os           - Comprehensive OS detection (portlist optional)")
	fmt.Println("\nExamples:")
	fmt.Println("  ./portfinder 192.168.1.1 80,443,22 syn")
	fmt.Println("  ./portfinder 192.168.1.0/24 1-1000 full")
	fmt.Println("  ./portfinder 192.168.1.1 os")
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
