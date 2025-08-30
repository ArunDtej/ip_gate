package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"math/big"

	"github.com/yl2chen/cidranger"
)

const socketPath = "/tmp/uds_check.sock"

var (
	ranger    cidranger.Ranger
	cidrCount int64    // number of CIDRs currently loaded
	ipCount   *big.Int // total number of IPs represented
	mu        sync.RWMutex
)

// downloadFile fetches a file from GitHub raw content URL
func downloadFile(githubURL, filename string) error {
	if strings.Contains(githubURL, "github.com") && strings.Contains(githubURL, "/blob/") {
		githubURL = strings.Replace(githubURL, "github.com", "raw.githubusercontent.com", 1)
		githubURL = strings.Replace(githubURL, "/blob/", "/", 1)
	}

	resp, err := http.Get(githubURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download file: %s", resp.Status)
	}

	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// loadData loads multiple CIDR files into a new cidranger instance
func loadData() (cidranger.Ranger, int64, *big.Int) {
	files := map[string]string{
		"level1.netset": "https://github.com/firehol/blocklist-ipsets/blob/master/firehol_level1.netset",
		"level2.netset": "https://github.com/firehol/blocklist-ipsets/blob/master/firehol_level2.netset",
		"proxy.netset":  "https://github.com/firehol/blocklist-ipsets/blob/master/firehol_proxies.netset",
	}

	for filename, url := range files {
		if err := downloadFile(url, filename); err != nil {
			fmt.Println("Error downloading", filename, ":", err)
		}
	}

	r := cidranger.NewPCTrieRanger()
	var counter int64
	totalIPs := big.NewInt(0)

	for filename := range files {
		file, err := os.Open(filename)
		if err != nil {
			fmt.Println("Error opening file:", filename, err)
			continue
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue // skip comments/empty lines
			}
			_, cidr, err := net.ParseCIDR(line)
			if err == nil {
				_ = r.Insert(cidranger.NewBasicRangerEntry(*cidr))
				counter++

				ones, bits := cidr.Mask.Size()
				size := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones)) // 2^(bits-ones)
				totalIPs.Add(totalIPs, size)
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Println("Error scanning file:", filename, err)
		}

		file.Close()
	}

	return r, counter, totalIPs
}

func refreshRanger(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		newR, newCIDRCount, newIPCount := loadData()
		mu.Lock()
		ranger = newR
		cidrCount = newCIDRCount
		ipCount = newIPCount
		mu.Unlock()
	}
}

// checkRequest handles IP lookups and commands
func checkRequest(req []byte) []byte {
	req = bytes.TrimSpace(req)
	if len(req) == 0 {
		return []byte("0\n")
	}

	mu.RLock()
	defer mu.RUnlock()

	// Special commands
	switch strings.ToUpper(string(req)) {
	case "SIZE":
		return []byte(fmt.Sprintf("%d\n", cidrCount))
	case "COUNT":
		if ipCount == nil {
			return []byte("0\n")
		}
		return []byte(fmt.Sprintf("%s\n", ipCount.String()))
	}

	// Otherwise, assume it's an IP
	parsed := net.ParseIP(string(req))
	if parsed == nil {
		return []byte("0\n") // invalid input
	}

	if ranger == nil {
		return []byte("0\n")
	}

	contained, _ := ranger.Contains(parsed)
	if contained {
		return []byte("1\n")
	}
	return []byte("0\n")
}

// handle UDS client connection
func handleConnection(c net.Conn) {
	defer c.Close()
	reader := bufio.NewReader(c)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		response := checkRequest(line)
		c.Write(response)
	}
}

func main() {
	os.Remove(socketPath)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	// initial load
	ranger, cidrCount, ipCount = loadData()

	// background refresh
	go refreshRanger(time.Hour)

	// accept clients
	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}
