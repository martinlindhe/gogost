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

// GOST R 34.13-2015 padding methods.
package gost3413

func PadSize(dataSize, blockSize int) int {
	if dataSize < blockSize {
		return blockSize - dataSize
	}
	if dataSize%blockSize == 0 {
		return 0
	}
	return blockSize - dataSize%blockSize
}

func Pad1(data []byte, blockSize int) []byte {
	padSize := PadSize(len(data), blockSize)
	if padSize == 0 {
		return data
	}
	return append(data, make([]byte, padSize)...)
}

func Pad2(data []byte, blockSize int) []byte {
	pad := make([]byte, 1+PadSize(len(data)+1, blockSize))
	pad[0] = byte(0x80)
	return append(data, pad...)
}

func Pad3(data []byte, blockSize int) []byte {
	if PadSize(len(data), blockSize) == 0 {
		return data
	}
	return Pad2(data, blockSize)
}
