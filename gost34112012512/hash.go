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

// GOST R 34.11-2012 512-bit hash function.
// RFC 6986.
package gost34112012512

import (
	"github.com/martinlindhe/gogost/internal/gost34112012"
)

const (
	BlockSize = gost34112012.BlockSize
	Size      = 64
)

func New() *gost34112012.Hash {
	return gost34112012.New(64)
}
