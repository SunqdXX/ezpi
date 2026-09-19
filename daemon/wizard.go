package main

import (
	_ "embed"
	"fmt"
	"math"
	"os"

	"golang.org/x/term"
)

//go:embed logo.txt
var logo string

func rainbow(text string) {
	color := term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""
	if !color {
		fmt.Print(text)
		return
	}
	const freq = 0.28
	y := 0.0
	col := 0.0
	for _, ch := range text {
		if ch == '\n' {
			fmt.Print("\x1b[0m\n")
			y++
			col = 0
			continue
		}
		i := col + y
		r := uint8(math.Sin(freq*i+0)*127 + 128)
		g := uint8(math.Sin(freq*i+2*math.Pi/3)*127 + 128)
		b := uint8(math.Sin(freq*i+4*math.Pi/3)*127 + 128)
		fmt.Printf("\x1b[38;2;%d;%d;%dm%c", r, g, b, ch)
		col++
	}
	fmt.Print("\x1b[0m")
}

func wizard() {
	fmt.Println()
	rainbow(logo)
	fmt.Println()
	fmt.Println("  A tiny DPI bypass for Linux. It unblocks apps and sites your")
	fmt.Println("  internet provider blocks -- without a VPN, without the speed and")
	fmt.Println("  memory cost of one. It runs in the background using about 15 MB.")
	fmt.Println()
	fmt.Println("  How it works, briefly:")
	fmt.Println("    Everything you send is encrypted except the NAME of the site")
	fmt.Println("    you are reaching -- and that name is what your provider matches")
	fmt.Println("    to block you. EzPi moves that name around on the wire so the")
	fmt.Println("    block cannot see it, while the real server still understands it.")
	fmt.Println("    It never decrypts your traffic and installs no certificate.")
	fmt.Println()
	fmt.Println("  Commands:")
	fmt.Println("    ezpi --enable      turn the bypass on")
	fmt.Println("    ezpi --disable     turn it off")
	fmt.Println("    ezpi               show the current situation")
	fmt.Println("    ezpi --check       test whether it actually beats your provider")
	fmt.Println()
}
