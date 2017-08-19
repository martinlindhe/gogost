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

type ECBEncrypter struct {
	c *Cipher
}

func (c *Cipher) NewECBEncrypter() *ECBEncrypter {
	e := ECBEncrypter{c}
	return &e
}

func (e *ECBEncrypter) CryptBlocks(dst, src []byte) {
	for i := 0; i < len(src); i += BlockSize {
		e.c.Encrypt(dst[i:i+BlockSize], src[i:i+BlockSize])
	}
}

func (e *ECBEncrypter) BlockSize() int {
	return e.c.BlockSize()
}

type ECBDecrypter struct {
	c *Cipher
}

func (c *Cipher) NewECBDecrypter() *ECBDecrypter {
	d := ECBDecrypter{c}
	return &d
}

func (e *ECBDecrypter) CryptBlocks(dst, src []byte) {
	for i := 0; i < len(src); i += BlockSize {
		e.c.Decrypt(dst[i:i+BlockSize], src[i:i+BlockSize])
	}
}

func (e *ECBDecrypter) BlockSize() int {
	return e.c.BlockSize()
}
