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

package gost3410

import (
	"errors"
	"math/big"

	"github.com/martinlindhe/gogost/gost34112012256"
	"github.com/martinlindhe/gogost/gost34112012512"
)

// RFC 7836 VKO GOST R 34.10-2012 256-bit key agreement function.
// UKM is user keying material, also called VKO-factor.
func (prv *PrivateKey) KEK2012256(pub *PublicKey, ukm *big.Int) ([]byte, error) {
	if prv.mode != Mode2012 {
		return nil, errors.New("KEK2012 can not be used in Mode2001")
	}
	key, err := prv.KEK(pub, ukm)
	if err != nil {
		return nil, err
	}
	h := gost34112012256.New()
	h.Write(key)
	return h.Sum(key[:0]), nil
}

// RFC 7836 VKO GOST R 34.10-2012 512-bit key agreement function.
// UKM is user keying material, also called VKO-factor.
func (prv *PrivateKey) KEK2012512(pub *PublicKey, ukm *big.Int) ([]byte, error) {
	if prv.mode != Mode2012 {
		return nil, errors.New("KEK2012 can not be used in Mode2001")
	}
	key, err := prv.KEK(pub, ukm)
	if err != nil {
		return nil, err
	}
	h := gost34112012512.New()
	h.Write(key)
	return h.Sum(key[:0]), nil
}
