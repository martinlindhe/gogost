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

import (
	"errors"
)

var (
	SeqMAC = Seq([]uint8{
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
	})
)

type MAC struct {
	c    *Cipher
	size int
	iv   []byte
	prev []byte
	buf  []byte
	n1   nv
	n2   nv
}

// Create MAC with given tag size and initial initialization vector.
// Size is in bytes and must be between 1 and 8. To be RFC conformant,
// iv must be the first block of the authenticated data, second and
// following ones are fed to Write function.
func (c *Cipher) NewMAC(size int, iv [BlockSize]byte) (*MAC, error) {
	if size == 0 || size > 8 {
		return nil, errors.New("Invalid tag size")
	}
	m := MAC{c: c, size: size, iv: iv[:]}
	n2, n1 := block2nvs(iv[:])
	m.iv = make([]byte, BlockSize)
	nvs2block(n1, n2, m.iv)
	m.prev = make([]byte, BlockSize)
	m.Reset()
	return &m, nil
}

func (m *MAC) Reset() {
	copy(m.prev, m.iv)
	m.buf = nil
}

func (m *MAC) BlockSize() int {
	return BlockSize
}

func (m *MAC) Size() int {
	return m.size
}

func (m *MAC) Write(b []byte) (int, error) {
	m.buf = append(m.buf, b...)
	for len(m.buf) >= BlockSize {
		for i := 0; i < BlockSize; i++ {
			m.prev[i] ^= m.buf[i]
		}
		m.n1, m.n2 = block2nvs(m.prev)
		m.n1, m.n2 = m.c.xcrypt(SeqMAC, m.n1, m.n2)
		nvs2block(m.n2, m.n1, m.prev)
		m.buf = m.buf[8:]
	}
	return len(b), nil
}

func (m *MAC) Sum(b []byte) []byte {
	if len(m.buf) == 0 {
		return append(b, m.prev[0:m.size]...)
	}
	buf := m.buf
	var i int
	for i = 0; i < BlockSize-len(m.buf); i++ {
		buf = append(buf, byte(0))
	}
	for i = 0; i < BlockSize; i++ {
		buf[i] ^= m.prev[i]
	}
	m.n1, m.n2 = block2nvs(buf)
	m.n1, m.n2 = m.c.xcrypt(SeqMAC, m.n1, m.n2)
	nvs2block(m.n2, m.n1, buf)
	return append(b, buf[0:m.size]...)
}
