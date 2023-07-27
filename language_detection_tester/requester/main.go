package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/davecgh/go-spew/spew"
	"google.golang.org/protobuf/proto"

	sysconfig "github.com/DataDog/datadog-agent/cmd/system-probe/config"
	languageDetectionProto "github.com/DataDog/datadog-agent/pkg/proto/pbgo/languagedetection"
)

var client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:    2,
		IdleConnTimeout: 30 * time.Second,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", "/opt/datadog-agent/run/sysprobe.sock")
		},
		TLSHandshakeTimeout:   1 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 50 * time.Millisecond,
	},
}

func usage() {
	fmt.Println("language-detection-test [pid]")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		usage()
		return
	}

	b, err := proto.Marshal(&languageDetectionProto.DetectLanguageRequest{Processes: []*languageDetectionProto.Process{{Pid: int32(pid)}}})
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://unix/"+string(sysconfig.LanguageDetectionModule)+"/detect", bytes.NewReader(b))
	if err != nil {
		panic(err)
	}

	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	if res.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("status is not ok: %v", res.StatusCode))
	}

	b, err = io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	spew.Dump(b)

	err = res.Body.Close()
	if err != nil {
		panic(err)
	}

	var resProto languageDetectionProto.DetectLanguageResponse
	err = proto.Unmarshal(b, &resProto)
	if err != nil {
		panic(err)
	}

	spew.Dump(&resProto)
}
