# port_server_version
使用nmap-service-probes模拟nmap进行端口扫描

使用方法

```go
package main

import (
	"fmt"
	"github.com/xiaoliu-z/port_server_version/scan_port"
)

func main() {
	banner, os, version, vendorProductName, server := scan_port.GetBannerServer("101.42.251.47", 22)
	fmt.Println(strconv.Quote(string(banner)))// 端口原始响应
	fmt.Println(os)                         // 操作系统版本
	fmt.Println(version)                    // 版本
	fmt.Println(vendorProductName)          // nmap指纹中的vendorProductName
	fmt.Println(server)                     // 服务名
}
```

输出结果:

```
"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"
Ubuntu Linux; protocol 2.0
8.9p1 Ubuntu 3
OpenSSH
ssh
```



原理:

将nmap项目下的nmap-service-probes解析成可直接使用的json文件

nmap-service-probes中包含着基础端口探测中所需的探针、探针使用条件、探针对应的指纹等等

当我们根据目标所开放的端口使用对应探针获取端口响应(banner)后，根据探针对应的指纹获取端口对应的服务及版本等信息。