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

// GOST 34.12-2015 128-bit (Кузнечик (Kuznechik)) block cipher.
package gost3412

const (
	BlockSize = 16
	KeySize   = 32
)

var (
	lc [BlockSize]byte = [BlockSize]byte{
		148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16,
		133, 32, 148, 1,
	}
	pi [256]byte = [256]byte{
		252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250,
		218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46,
		153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249,
		24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139,
		1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6,
		11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81,
		234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206,
		204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19,
		71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123,
		154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
		50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198,
		128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168,
		67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224,
		15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80,
		78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68,
		26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70,
		146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213,
		149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55,
		107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76,
		63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
		32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208,
		190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180,
		192, 209, 102, 175, 194, 57, 75, 99, 182,
	}
	piInv [256]byte
	cBlk  [32]*[BlockSize]byte
)

func gf(a, b byte) (c byte) {
	for b > 0 {
		if b&1 > 0 {
			c ^= a
		}
		if a&0x80 > 0 {
			a = (a << 1) ^ 0xC3
		} else {
			a <<= 1
		}
		b >>= 1
	}
	return
}

func l(blk *[BlockSize]byte, rounds int) {
	var t byte
	var i int
	for ; rounds > 0; rounds-- {
		t = blk[15]
		for i = 14; i >= 0; i-- {
			blk[i+1] = blk[i]
			t ^= gf(blk[i], lc[i])
		}
		blk[0] = t
	}
}

func lInv(blk *[BlockSize]byte) {
	var t byte
	var i int
	for n := 0; n < BlockSize; n++ {
		t = blk[0]
		for i = 0; i < 15; i++ {
			blk[i] = blk[i+1]
			t ^= gf(blk[i], lc[i])
		}
		blk[15] = t
	}
}

func init() {
	piInvP := new([256]byte)
	for i := 0; i < 256; i++ {
		piInvP[int(pi[i])] = byte(i)
	}
	piInv = *piInvP
	CP := new([32]*[BlockSize]byte)
	for i := 0; i < 32; i++ {
		CP[i] = new([BlockSize]byte)
		CP[i][15] = byte(i) + 1
		l(CP[i], 16)
	}
	cBlk = *CP
}

func s(blk *[BlockSize]byte) {
	for i := 0; i < BlockSize; i++ {
		blk[i] = pi[int(blk[i])]
	}
}

func xor(dst, src1, src2 *[BlockSize]byte) {
	for i := 0; i < BlockSize; i++ {
		dst[i] = src1[i] ^ src2[i]
	}
}

type Cipher struct {
	ks [10]*[BlockSize]byte
}

func (c *Cipher) BlockSize() int {
	return BlockSize
}

func NewCipher(key [KeySize]byte) *Cipher {
	ks := new([10]*[BlockSize]byte)
	kr0 := new([BlockSize]byte)
	kr1 := new([BlockSize]byte)
	krt := new([BlockSize]byte)
	copy(kr0[:], key[:BlockSize])
	copy(kr1[:], key[BlockSize:])
	ks[0] = new([BlockSize]byte)
	ks[1] = new([BlockSize]byte)
	copy(ks[0][:], kr0[:])
	copy(ks[1][:], kr1[:])
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			xor(krt, kr0, cBlk[8*i+j])
			s(krt)
			l(krt, 16)
			xor(krt, krt, kr1)
			copy(kr1[:], kr0[:])
			copy(kr0[:], krt[:])
		}
		ks[2+2*i] = new([BlockSize]byte)
		copy(ks[2+2*i][:], kr0[:])
		ks[2+2*i+1] = new([BlockSize]byte)
		copy(ks[2+2*i+1][:], kr1[:])
	}
	return &Cipher{*ks}
}

func (c *Cipher) Encrypt(dst, src []byte) {
	blk := new([BlockSize]byte)
	copy(blk[:], src)
	for i := 0; i < 9; i++ {
		xor(blk, blk, c.ks[i])
		s(blk)
		l(blk, 16)
	}
	xor(blk, blk, c.ks[9])
	copy(dst[:BlockSize], blk[:])
}

func (c *Cipher) Decrypt(dst, src []byte) {
	blk := new([BlockSize]byte)
	copy(blk[:], src)
	var n int
	for i := 9; i > 0; i-- {
		xor(blk, blk, c.ks[i])
		lInv(blk)
		for n = 0; n < BlockSize; n++ {
			blk[n] = piInv[int(blk[n])]
		}
	}
	xor(blk, blk, c.ks[0])
	copy(dst[:BlockSize], blk[:])
}
