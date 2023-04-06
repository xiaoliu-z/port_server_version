package main

import (
	"fmt"
	"github.com/xiaoliu-z/port_server_version/scan_port"
	"strconv"
)

func main() {
	banner, os, version, vendorProductName, server := scan_port.GetBannerServer("101.42.251.47", 22)
	fmt.Println(strconv.Quote(string(banner)))
	fmt.Println(os)
	fmt.Println(version)
	fmt.Println(vendorProductName)
	fmt.Println(server)
}
