package kktool

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/chai2010/webp"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// Part1: hash 加密密码保存入库，避免密码可以被重现
func EncodePassword(passwordstr string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(passwordstr), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(hash)

	encodePW := string(hash) // 保存在数据库的密码，虽然每次生成都不同，只需保存一份即可
	fmt.Println(encodePW)
	return encodePW
}

func ComparePassword(rightpwd, inputpwd string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(rightpwd), []byte(inputpwd))
	return err == nil
}

// Part2: 数据脱敏，支持打星号
func HideStar(str string) (result string) {
	if str == "" {
		return "***"
	}
	// 邮箱
	if strings.Contains(str, "@") {
		res := strings.Split(str, "@")
		if len(res[0]) < 3 {
			resString := "***"
			result = resString + "@" + res[1]
		} else {
			res2 := Substr2(str, 0, 3)
			resString := res2 + "***"
			result = resString + "@" + res[1]
		}
		return result
	} else {
		reg := `^1[0-9]\d{9}$`
		rgx := regexp.MustCompile(reg)
		mobileMatch := rgx.MatchString(str)
		if mobileMatch {
			result = Substr2(str, 0, 3) + "****" + Substr2(str, 7, 11)
		} else {
			nameRune := []rune(str)
			lens := len(nameRune)
			// 手机号
			if lens <= 1 {
				result = "***"
			} else if lens == 2 {
				result = string(nameRune[:1]) + "*"
			} else if lens == 3 {
				result = string(nameRune[:1]) + "*" + string(nameRune[2:3])
			} else if lens == 4 {
				result = string(nameRune[:1]) + "**" + string(nameRune[lens-1:lens])
			} else if lens > 4 {
				result = string(nameRune[:2]) + "***" + string(nameRune[lens-2:lens])
			}
		}
		return
	}
}

func Substr2(str string, start int, end int) string {
	rs := []rune(str)
	return string(rs[start:end])
}

// Part3: struct to map // map to struct

func StructToMap(input interface{}) *map[string]interface{} {
	var inInterface map[string]interface{}
	inrec, _ := json.Marshal(input)
	json.Unmarshal(inrec, &inInterface)
	return &inInterface
}

// 支持泛型
func MapToStruct[T any](data interface{}, res T) T {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("recover value is", r)
		}
	}()
	mapstructure.Decode(data, &res)
	return res
}

// Part4: Execute cmd in os

type Charset string

const (
	UTF8    = Charset("UTF-8")
	GB18030 = Charset("GB18030")
)

func ConvertByte2String(byte []byte, charset Charset) string {

	var str string
	switch charset {
	case GB18030:
		decodeBytes, _ := simplifiedchinese.GB18030.NewDecoder().Bytes(byte)
		str = string(decodeBytes)
	case UTF8:
		fallthrough
	default:
		str = string(byte)
	}

	return str
}

func ExecuteCommand(cmdStr string) (results string, err error) {
	// Create the command object
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", cmdStr) // Replace with your command and arguments
	} else {
		cmd = exec.CommandContext(ctx, cmdStr) // Replace with your command and arguments
	}

	// Set up the output pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}

	// Start the command
	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}

	// Create scanners for stdout and stderr
	// Set output pipe encoding to UTF-8
	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)

	outputChan := make(chan string)
	// Start goroutines to read stdout and stderr asynchronously
	go func() {
		defer close(outputChan)
		for stdoutScanner.Scan() {
			// line := stdoutScanner.Text()
			line := ConvertByte2String(stdoutScanner.Bytes(), GB18030)
			fmt.Println("stdout:", line)
			outputChan <- line
			// Process stdout line as needed
		}
	}()

	go func() {
		for stderrScanner.Scan() {
			// line := stderrScanner.Text()
			garbledStr := ConvertByte2String(stderrScanner.Bytes(), GB18030)
			fmt.Println("stderr:", garbledStr)

			// Process stderr line as needed
		}
	}()
	// Read output from the channel
	outbuilder := strings.Builder{}
	for line := range outputChan {
		fmt.Println("Output:", line)
		outbuilder.WriteString(line + "\n")
	}
	results = outbuilder.String()
	// Wait for the command to finish or a timeout
	timeout := time.After(30 * time.Second)
	select {
	case <-timeout:
		// Timeout occurred
		fmt.Println("Command timed out")
	case <-cmdDone(cmd):
		// Command completed successfully
		fmt.Println("Command completed")
	}

	fmt.Println("Done")
	return
}

// Helper function to wait for the command to finish
func cmdDone(cmd *exec.Cmd) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		cmd.Wait()
		close(done)
	}()
	return done
}

// Part 5 : random strings
// 产生随机字符串
// size参数为长度
func RandomStringWithSize(size int) string {
	char := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rand.NewSource(time.Now().UnixNano())
	var s bytes.Buffer
	for i := 0; i < size; i++ {
		s.WriteByte(char[rand.Int63()%int64(len(char))])
	}
	return s.String()
}

// Part6: convert string from ...
func ConvertString(inter interface{}, precs ...int) string {
	switch v := inter.(type) {
	case string:
		return v
	case float64:
		prec := 0
		if len(precs) > 0 {
			prec = precs[0]
		}
		return strconv.FormatFloat(v, 'f', prec, 64)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case int:
		return strconv.Itoa(v)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	default:
		return fmt.Sprintf("%v", inter)
	}
}

// ConvertToInt 字符串转int
func ConvertToInt(s string, defaultVal ...int) int {
	getDefault := func() int {
		if len(defaultVal) > 0 {
			return defaultVal[0]
		}
		return 0
	}

	if s == "" {
		return getDefault()
	}

	i, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		msg := "kktool ConvertToInt strconv.Atoi error:" + err.Error()
		// 加上文件调用和行号
		_, callerFile, line, ok := runtime.Caller(1)
		if ok {
			msg += fmt.Sprintf("file:%s,line:%d", callerFile, line)
		}
		return getDefault()
	}

	return i
}

// ConverToInt64 字符串转int64
func ConverToInt64(s string, defaultVal ...int64) int64 {
	getDefault := func() int64 {
		if len(defaultVal) > 0 {
			return defaultVal[0]
		}
		return 0
	}

	if s == "" {
		return getDefault()
	}

	i, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		msg := "kktool ConverToInt64 strconv.ParseInt error:" + err.Error()
		// 加上文件调用和行号
		_, callerFile, line, ok := runtime.Caller(1)
		if ok {
			msg += fmt.Sprintf("file:%s,line:%d", callerFile, line)
		}
		return getDefault()
	}

	return i
}

func getFloatDefault(defaultVals ...float64) float64 {
	if len(defaultVals) > 0 {
		return defaultVals[0]
	}
	return 0.0
}

func StringToFloat(s string, defaultVals ...float64) float64 {
	if s == "" {
		return getFloatDefault()
	}

	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		log.Println("kktool StringToFloat strconv.ParseFloat error:", err)
		return getFloatDefault()
	}

	return f
}

func ConverToFloat(inter interface{}, defaultVals ...float64) float64 {
	switch v := inter.(type) {
	case float64:
		return v
	case string:
		return StringToFloat(v, defaultVals...)
	case int64:
		return float64(v)
	case float32:
		return float64(v)
	default:
		return getFloatDefault(defaultVals...)
	}
}

// Ip2long 将 IPv4 字符串形式转为 uint32
func Ip2long(ipstr string) uint32 {
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

// Part6: returns MD5 checksum of file
// MD5sum returns MD5 checksum of filename
func MD5sum(filename string) (string, error) {
	const bufferSize = 65536
	if info, err := os.Stat(filename); err != nil {
		return "", err
	} else if info.IsDir() {
		return "", nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	for buf, reader := make([]byte, bufferSize), bufio.NewReader(file); ; {
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}

		hash.Write(buf[:n])
	}

	checksum := fmt.Sprintf("%x", hash.Sum(nil))
	return checksum, nil
}

// ImageBytes2WebpBytes 将图片转为webp
// inputFile 图片字节切片（仅限gif,jpeg,png格式）
// outputFile webp图片字节切片
// 图片质量
func ImageBytes2WebpBytes(input []byte, quality float32) ([]byte, error) {

	//解析图片
	img, format, err := image.Decode(bytes.NewBuffer(input))
	if err != nil {
		log.Println("图片解析失败")
		return nil, err
	}

	log.Println("原始图片格式：", format)

	//转为webp
	webpBytes, err := webp.EncodeRGBA(img, quality)

	if err != nil {
		log.Println("解析图片失败", err)
		return nil, err
	}

	return webpBytes, nil
}

// Image2Webp 将图片转为webp
// inputFile 图片路径（仅限gif,jpeg,png格式）
// outputFile 图片输出路径
// 图片质量
func Image2Webp(inputFile string, outputFile string, quality float32) error {

	// 读取文件
	fileBytes, err := os.ReadFile(inputFile)
	if err != nil {
		log.Println("读取文件失败:", err)
		return err
	}

	webpBytes, err := ImageBytes2WebpBytes(fileBytes, quality)

	if err != nil {
		log.Println("解析图片失败", err)
		return err
	}

	if err = os.WriteFile(outputFile, webpBytes, 0666); err != nil {
		log.Println("图片写入失败", err)
		return err
	}

	originalSize := len(fileBytes)
	webpSize := len(webpBytes)
	log.Printf("原始大小:%d k,转换后大小:%d k,压缩比:%d %% \n", originalSize/1024, webpSize/1024, webpSize*100/originalSize)

	return nil
}
