package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

func checkerr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
}

func main() {
	if len(os.Args) > 1 {
		fmt.Println(os.Args[1])
		if os.Args[1] == "jia" {
			nr, err := ioutil.ReadFile(os.Args[2])
			checkerr(err)
			str := string(nr)
			//str = strings.Replace(str, "\\x", "", -1)[1:]
			str = strings.Replace(str, "\\x", "", -1)
			encodeString := base64.StdEncoding.EncodeToString([]byte(str))
			rand.Seed(time.Now().Unix())
			passwd := rand_int()
			ASE_str := Get_Aes_encry(encodeString, passwd)
			result := base64.StdEncoding.EncodeToString([]byte(passwd + ASE_str))
			errr := Py_Writefile("./shellcode.txt", result, "w")
			checkerr(errr)
			fmt.Println(result)
		}else if os.Args[1] == "jie" {
			nr, err := ioutil.ReadFile(os.Args[1])
			checkerr(err)
			str := string(nr)
			jiemi(str)
		}
	}
}

func unpadding(src []byte) []byte {
	n:=len(src)
	unpadnum:=int(src[n-1])
	return src[:n-unpadnum]
}

func decryptAES(src []byte,key []byte) []byte {
	block,_:=aes.NewCipher(key)
	blockmode:=cipher.NewCBCDecrypter(block,key)
	blockmode.CryptBlocks(src,src)
	src=unpadding(src)
	return src
}

func Get_Aes_decode(str string, keys string) string {
	x:=[]byte(str)
	key:=[]byte(keys)
	x1:=decryptAES(x,key)
	return string(x1)
}

func jiemi(str string) {
	decodeBytes, err := base64.StdEncoding.DecodeString(str)
	checkerr(err)
	key := string(decodeBytes)[0:16]
	a := Get_Aes_decode(strings.Replace(string(decodeBytes),key,"",1),key)

	decodeBytes1, err := base64.StdEncoding.DecodeString(a)
	checkerr(err)
	fmt.Println(string(decodeBytes1))
}

func rand_int() string {
	var str string
	rand.Seed(time.Now().Unix())
	for i:=0;i<16;i++{
		str += strconv.Itoa(rand.Intn(9) + 1)
	}
	return str
}

func Py_Writefile(fileName string, nr string, fangshi string) error {
	var f *os.File
	var err error
	if fangshi == "w" {
		f, err = os.OpenFile(fileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	} else if fangshi == "a" {
		f, err = os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0644)
	} else {
		return errors.New("error a/w")
	}
	if err != nil {
		fmt.Println("file create failed. err: " + err.Error())
	} else {
		n, _ := f.Seek(0, os.SEEK_END)
		_, err = f.WriteAt([]byte(nr), n)
		defer f.Close()
	}
	return nil
}

func padding(src []byte, blocksize int) []byte {
	padnum := blocksize - len(src)%blocksize
	pad := bytes.Repeat([]byte{byte(padnum)}, padnum)
	return append(src, pad...)
}

func encryptAES(src []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	src = padding(src, block.BlockSize())
	blockmode := cipher.NewCBCEncrypter(block, key)
	blockmode.CryptBlocks(src, src)
	return src
}

func Get_Aes_encry(str string, keys string) string {
	x := []byte(str)
	key := []byte(keys)
	x1 := encryptAES(x, key)
	return string(x1)
}
