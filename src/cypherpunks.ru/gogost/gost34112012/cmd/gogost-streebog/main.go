// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2016 Sergey Matveev <stargrave@stargrave.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Command-line 34.11-2012 hash function.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"cypherpunks.ru/gogost"
	"cypherpunks.ru/gogost/gost34112012"
)

var (
	digestSize = flag.Int("size", 256, "Digest size (either 256 or 512)")
	version    = flag.Bool("version", false, "Print version information")
)

func main() {
	flag.Parse()
	if *version {
		fmt.Println(gogost.Version)
		return
	}
	h := gost34112012.New(*digestSize)
	io.Copy(h, os.Stdin)
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
}
