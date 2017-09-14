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
	"math/big"
)

func (prv *PrivateKey) KEK(pub *PublicKey, ukm *big.Int) ([]byte, error) {
	keyX, keyY, err := prv.c.Exp(prv.key, pub.x, pub.y)
	if err != nil {
		return nil, err
	}
	keyX, keyY, err = prv.c.Exp(ukm, keyX, keyY)
	if err != nil {
		return nil, err
	}
	pk := PublicKey{prv.c, prv.mode, keyX, keyY}
	return pk.Raw(), nil
}
