package main

import (
	"log"

	"fort/internal/cli"
)

func main() {
	if err := cli.Run(); err != nil {
		log.Fatal(err)
	}
}
