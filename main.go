package arsenal

import (
	"fmt"
	"testing"
)

func TestDemo(t *testing.T) {
	fmt.Println("testing")
}

func TestMain(m *testing.M) {
	fmt.Println("TestWorld")
}

go test -v  .\hello_test.go -test.run TestDemo
go test -v  .\hello_test.go
