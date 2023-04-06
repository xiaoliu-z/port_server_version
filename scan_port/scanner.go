package scan_port

import (
	"fmt"
	"github.com/dlclark/regexp2"
	"net"
	"strconv"
	"strings"
)

func probeScan(ip string, port int, probe []byte) []byte {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Printf("conn server failed, err:%v\n", err)
		return []byte("")
	}
	if len(probe) > 0 {
		_, err = conn.Write(probe)
		if err != nil {
			fmt.Printf("send failed, err:%v\n", err)
			return []byte("")
		}
	}
	// 从服务端接收回复消息
	var buf [1024]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		fmt.Printf("read failed:%v\n", err)
		return []byte("")
	}

	return buf[:n]
}

func GetBannerServer(ip string, port int) ([]byte, string, string, string, string) {
	var ret []byte
	var probeId int
	// nmap逻辑是遍历探针 但是遍历过程中依照优先级选择性遍历
	for i := 0; i < len(RarityProbes); i++ {
		for rarity := 0; rarity <= 9; rarity++ {
			if RarityProbes[i].Rarity == rarity {
				if RarityProbes[i].Ports.Has(port) || rarity == 0 {
					// socket连接目标
					ret = probeScan(ip, port, RarityProbes[i].ProbeString)
					if len(ret) > 0 {
						probeId = RarityProbes[i].ProbeId
					}
				}
			}
		}
	}

	//*************************************开始使用指纹端口响应进行判断
	// 对指纹进行正则匹配确定服务及版本
	for i := 0; i < len(Rules[probeId]); i++ {
		re, err := regexp2.Compile(Rules[probeId][i].Pattern, 0)
		if err != nil {
			fmt.Println(err)
			continue
		}

		if match, err := re.MatchString(string(ret)); match == true && err == nil {
			var version string
			var os string
			if strings.Contains(Rules[probeId][i].VersionInfo.Version, "$") && len(Rules[probeId][i].VersionInfo.Version) > 1 {
				m, _ := re.FindStringMatch(string(ret))
				gps := m.Groups()
				for {
					if strings.Contains(Rules[probeId][i].VersionInfo.Version, "$") {
						tmp_str := Rules[probeId][i].VersionInfo.Version
						tmp_index := strings.Index(tmp_str, "$")
						index, _ := strconv.Atoi(tmp_str[tmp_index+1 : tmp_index+2])
						version := gps[index].String()
						Rules[probeId][i].VersionInfo.Version = strings.Replace(tmp_str, tmp_str[tmp_index:tmp_index+2], version, 1)
					} else {
						break
					}
				}
				version = Rules[probeId][i].VersionInfo.Version
			} else {
				version = Rules[probeId][i].VersionInfo.Version
			}
			if strings.Contains(Rules[probeId][i].VersionInfo.Info, "$") && len(Rules[probeId][i].VersionInfo.Info) > 1 {
				m, _ := re.FindStringMatch(string(ret))
				gps := m.Groups()
				for {
					if strings.Contains(Rules[probeId][i].VersionInfo.Info, "$") {
						tmp_str := Rules[probeId][i].VersionInfo.Info
						tmp_index := strings.Index(tmp_str, "$")
						index, _ := strconv.Atoi(tmp_str[tmp_index+1 : tmp_index+2])
						tmp := gps[index].String()
						Rules[probeId][i].VersionInfo.Info = strings.Replace(tmp_str, tmp_str[tmp_index:tmp_index+2], tmp, 1)
					} else {
						break
					}
				}
				os = Rules[probeId][i].VersionInfo.Info
			} else {
				os = Rules[probeId][i].VersionInfo.Info
			}

			return ret, os, version, Rules[probeId][i].VersionInfo.VendorProductName, Rules[probeId][i].Name
		}

	}

	return ret, "", "", "", ""
}