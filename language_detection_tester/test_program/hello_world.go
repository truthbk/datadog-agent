package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	for {
		fmt.Println("I am pid", os.Getpid())
		time.Sleep(time.Second)
	}
}
