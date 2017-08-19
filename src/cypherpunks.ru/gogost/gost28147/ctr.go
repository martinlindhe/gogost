// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2017 Sergey Matveev <stargrave@stargrave.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this program.  If not, see
// <http://www.gnu.org/licenses/>.

package gost28147

type CTR struct {
	c  *Cipher
	n1 nv
	n2 nv
}

func (c *Cipher) NewCTR(iv [BlockSize]byte) *CTR {
	n1, n2 := block2nvs(iv[:])
	n2, n1 = c.xcrypt(SeqEncrypt, n1, n2)
	return &CTR{c, n1, n2}
}

func (c *CTR) XORKeyStream(dst, src []byte) {
	var n1t nv
	var n2t nv
	block := make([]byte, BlockSize)
	i := 0
	var n int
MainLoop:
	for {
		c.n1 += 0x01010101 // C2
		c.n2 += 0x01010104 // C1
		if c.n2 >= 1<<32-1 {
			c.n2 -= 1<<32 - 1
		}
		n1t, n2t = c.c.xcrypt(SeqEncrypt, c.n1, c.n2)
		nvs2block(n1t, n2t, block)
		for n = 0; n < BlockSize; n++ {
			if i*BlockSize+n == len(src) {
				break MainLoop
			}
			dst[i*BlockSize+n] = src[i*BlockSize+n] ^ block[n]
		}
		i++
	}
	return
}
