package scanner

import (
	"fmt"
	"portfinder/vars"
	"strings"
	"sync"
)

// defaultClosedPort is a port number assumed to be closed on remote hosts,
// used as a reference point for OS fingerprint probes.
const defaultClosedPort = 65530

// OpenclawResult holds the combined scan result for a single IP.
type OpenclawResult struct {
	IP         string
	OpenPorts  []int
	OSGuess    string
	Confidence int
}

// OpenclawScan performs a comprehensive scan on the given IP list and port list:
//  1. SYN scan to discover open ports.
//  2. OS fingerprint detection on each host that has at least one open port.
//
// dbPath is the path to the nmap-os-db file used for OS detection.
// It returns a slice of OpenclawResult, one per IP.
func OpenclawScan(ips []string, ports []int, dbPath string) []OpenclawResult {
	// Phase 1: SYN port scan across all IPs.
	fmt.Println("[openclaw] Phase 1: SYN port scan")
	StartSynListener()
	synScanner := NewsynScanner()

	tasks := make([]map[string]int, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, port := range ports {
			tasks = append(tasks, map[string]int{ip: port})
		}
	}
	AssigningTasks(tasks, synScanner)

	// Phase 2: OS detection for each IP with open ports.
	fmt.Println("[openclaw] Phase 2: OS detection")
	results := make([]OpenclawResult, 0, len(ips))
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}

	for _, ip := range ips {
		wg.Add(1)
		go func(ipStr string) {
			defer wg.Done()

			res := OpenclawResult{IP: ipStr}

			// Collect open ports found in phase 1.
			if v, ok := vars.Result.Load(ipStr); ok {
				if openPorts, ok := v.([]int); ok {
					res.OpenPorts = openPorts
				}
			}

			// Determine open port and closed port for OS detection.
			openPort := -1
			if len(res.OpenPorts) > 0 {
				openPort = res.OpenPorts[0]
			}
			closedPort := defaultClosedPort

			if openPort == -1 {
				fmt.Printf("[openclaw] %s: no open ports found, skipping OS detection\n", ipStr)
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
				return
			}

			fmt.Printf("[openclaw] %s: running OS detection (open=%d)\n", ipStr, openPort)
			osScanner := NewOSScanner(ipStr, openPort, closedPort)
			if err := osScanner.LoadNmapOSDB(dbPath); err != nil {
				fmt.Printf("[openclaw] %s: failed to load OS DB: %v\n", ipStr, err)
			} else {
				fingerprint, err := osScanner.DoOSDetection()
				if err != nil {
					fmt.Printf("[openclaw] %s: OS detection error: %v\n", ipStr, err)
				} else {
					res.OSGuess = fingerprint.OSGuess
					res.Confidence = fingerprint.Confidence
				}
			}

			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return results
}

// PrintOpenclawResults prints the combined scan results to stdout.
func PrintOpenclawResults(results []OpenclawResult) {
	fmt.Println("\n========== OpenClaw Scan Results ==========")
	for _, r := range results {
		fmt.Printf("\nHost: %s\n", r.IP)
		if len(r.OpenPorts) == 0 {
			fmt.Println("  Open Ports : none")
		} else {
			fmt.Printf("  Open Ports : %v\n", r.OpenPorts)
		}
		if r.OSGuess == "" {
			fmt.Println("  OS Guess   : unknown")
		} else {
			fmt.Printf("  OS Guess   : %s (confidence: %d%%)\n", r.OSGuess, r.Confidence)
		}
		fmt.Println("  " + strings.Repeat("-", 48))
	}
	fmt.Println("===========================================")
}
