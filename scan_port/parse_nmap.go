package scan_port

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
)

type Nmap []struct {
	Protocol     string   `json:"protocol"`
	Probename    string   `json:"probename"`
	Probestring  string   `json:"probestring"`
	Ports        []string `json:"ports"`
	Sslports     []string `json:"sslports"`
	Totalwaitms  string   `json:"totalwaitms"`
	Tcpwrappedms string   `json:"tcpwrappedms"`
	Rarity       string   `json:"rarity"`
	Fallback     string   `json:"fallback"`
	Matches      []struct {
		Pattern     string `json:"pattern"`
		Name        string `json:"name"`
		PatternFlag string `json:"pattern_flag"`
		Versioninfo struct {
			Cpename           string `json:"cpename"`
			Devicetype        string `json:"devicetype"`
			Hostname          string `json:"hostname"`
			Info              string `json:"info"`
			Operatingsystem   string `json:"operatingsystem"`
			Vendorproductname string `json:"vendorproductname"`
			Version           string `json:"version"`
		} `json:"versioninfo"`
	} `json:"matches"`
	Softmatches []struct {
		Pattern     string `json:"pattern"`
		Name        string `json:"name"`
		PatternFlag string `json:"pattern_flag"`
		Versioninfo struct {
			Cpename           string `json:"cpename"`
			Devicetype        string `json:"devicetype"`
			Hostname          string `json:"hostname"`
			Info              string `json:"info"`
			Operatingsystem   string `json:"operatingsystem"`
			Vendorproductname string `json:"vendorproductname"`
			Version           string `json:"version"`
		} `json:"versioninfo"`
	} `json:"softmatches"`
}

type Probe struct {
	ProbeId     int
	TotalWaitMs int
	Rarity      int
	Ports       Set
	SslPorts    Set
	ProbeString []byte
}

type VersionInfo struct {
	CpeName           string
	DeviceType        string
	Hostname          string
	Info              string
	OperatingSystem   string
	VendorProductName string
	Version           string
}

type Rule struct {
	ProbeId     int
	Pattern     string
	Name        string
	VersionInfo VersionInfo
}

// Set 自定义一个Set *****************************************
type Set map[int]struct{}

func (s Set) Has(key int) bool {
	_, ok := s[key]
	return ok
}

func (s Set) Add(key int) {
	s[key] = struct{}{}
}

func (s Set) Delete(key int) {
	delete(s, key)
}

// 将nmap-server-probe中的字符串端口转变为数字 并写入set中
func createPort(ports []string, tmpS Set) {
	for _, port := range ports {
		if strings.Contains(port, "-") {
			tmpPorts := strings.Split(port, "-")
			tmpl, tmpr := tmpPorts[0], tmpPorts[1]
			l, _ := strconv.Atoi(tmpl)
			r, _ := strconv.Atoi(tmpr)
			for i := l; i <= r; i++ {
				tmpS.Add(i)
			}
		} else {
			tmpPort, _ := strconv.Atoi(port)
			tmpS.Add(tmpPort)
		}
	}
}

func initNmap() {
	var nmap Nmap

	jsonFile, err := os.Open("data/nmap.json")
	if err != nil { // 打开nmap.json失败
	}
	byteValue, _ := io.ReadAll(jsonFile)
	_ = json.Unmarshal(byteValue, &nmap)
	// json解析失败进行处理
	_ = jsonFile.Close()

	for i := 0; i < len(nmap); i++ {
		var PortSet = make(Set)
		var SslPortSet = make(Set)
		TotalWaitMs, _ := strconv.Atoi(nmap[i].Totalwaitms)
		Rarity, _ := strconv.Atoi(nmap[i].Rarity)
		ProbeString, _ := base64.StdEncoding.DecodeString(nmap[i].Probestring)
		createPort(nmap[i].Ports, PortSet)
		createPort(nmap[i].Sslports, SslPortSet)
		RarityProbes = append(RarityProbes, Probe{
			ProbeId:     i,
			TotalWaitMs: TotalWaitMs,
			Rarity:      Rarity,
			Ports:       PortSet,
			SslPorts:    SslPortSet,
			ProbeString: ProbeString,
		})

		if len(nmap[i].Matches) > 0 {
			for j := 0; j < len(nmap[i].Matches); j++ {
				Rules[i] = append(Rules[i], Rule{
					ProbeId: i,
					Pattern: nmap[i].Matches[j].Pattern,
					Name:    nmap[i].Matches[j].Name,
					VersionInfo: VersionInfo{
						CpeName:           nmap[i].Matches[j].Versioninfo.Cpename,
						DeviceType:        nmap[i].Matches[j].Versioninfo.Devicetype,
						Hostname:          nmap[i].Matches[j].Versioninfo.Hostname,
						Info:              nmap[i].Matches[j].Versioninfo.Info,
						OperatingSystem:   nmap[i].Matches[j].Versioninfo.Operatingsystem,
						VendorProductName: nmap[i].Matches[j].Versioninfo.Vendorproductname,
						Version:           nmap[i].Matches[j].Versioninfo.Version,
					},
				})
			}

		}
		if len(nmap[i].Softmatches) > 0 {
			for j := 0; j < len(nmap[i].Softmatches); j++ {
				Rules[i] = append(Rules[i], Rule{
					ProbeId: i,
					Pattern: nmap[i].Softmatches[j].Pattern,
					Name:    nmap[i].Softmatches[j].Name,
					VersionInfo: VersionInfo{
						CpeName:           nmap[i].Softmatches[j].Versioninfo.Cpename,
						DeviceType:        nmap[i].Softmatches[j].Versioninfo.Devicetype,
						Hostname:          nmap[i].Softmatches[j].Versioninfo.Hostname,
						Info:              nmap[i].Softmatches[j].Versioninfo.Info,
						OperatingSystem:   nmap[i].Softmatches[j].Versioninfo.Operatingsystem,
						VendorProductName: nmap[i].Softmatches[j].Versioninfo.Vendorproductname,
						Version:           nmap[i].Softmatches[j].Versioninfo.Version,
					},
				})
			}
		}

	}

}

// RarityProbes 按优先级排列存储的探针
var RarityProbes []Probe

// Rules 按照探针存储的指纹
var Rules = make(map[int][]Rule, 200)

func init() {
	initNmap()
}
