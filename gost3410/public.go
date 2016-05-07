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

package gost3410

import (
	"errors"
	"math/big"
)

type PublicKey struct {
	c  *Curve
	ds int
	x  *big.Int
	y  *big.Int
}

func NewPublicKey(curve *Curve, ds DigestSize, raw []byte) (*PublicKey, error) {
	if len(raw) != 2*int(ds) {
		return nil, errors.New("Invalid public key length")
	}
	key := make([]byte, 2*int(ds))
	copy(key, raw)
	reverse(key)
	return &PublicKey{
		curve,
		int(ds),
		bytes2big(key[int(ds) : 2*int(ds)]),
		bytes2big(key[:int(ds)]),
	}, nil
}

func (pk *PublicKey) Raw() []byte {
	raw := append(pad(pk.y.Bytes(), pk.ds), pad(pk.x.Bytes(), pk.ds)...)
	reverse(raw)
	return raw
}

func (pk *PublicKey) VerifyDigest(digest, signature []byte) (bool, error) {
	if len(digest) != pk.ds {
		return false, errors.New("Invalid input digest length")
	}
	if len(signature) != 2*pk.ds {
		return false, errors.New("Invalid signature length")
	}
	s := bytes2big(signature[:pk.ds])
	r := bytes2big(signature[pk.ds:])
	if r.Cmp(zero) <= 0 || r.Cmp(pk.c.Q) >= 0 || s.Cmp(zero) <= 0 || s.Cmp(pk.c.Q) >= 0 {
		return false, nil
	}
	e := bytes2big(digest)
	e.Mod(e, pk.c.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}
	v := big.NewInt(0)
	v.ModInverse(e, pk.c.Q)
	z1 := big.NewInt(0)
	z2 := big.NewInt(0)
	z1.Mul(s, v)
	z1.Mod(z1, pk.c.Q)
	z2.Mul(r, v)
	z2.Mod(z2, pk.c.Q)
	z2.Sub(pk.c.Q, z2)
	p1x, p1y, err := pk.c.Exp(z1, pk.c.Bx, pk.c.By)
	if err != nil {
		return false, err
	}
	q1x, q1y, err := pk.c.Exp(z2, pk.x, pk.y)
	if err != nil {
		return false, err
	}
	lm := big.NewInt(0)
	lm.Sub(q1x, p1x)
	if lm.Cmp(zero) < 0 {
		lm.Add(lm, pk.c.P)
	}
	lm.ModInverse(lm, pk.c.P)
	z1.Sub(q1y, p1y)
	lm.Mul(lm, z1)
	lm.Mod(lm, pk.c.P)
	lm.Mul(lm, lm)
	lm.Mod(lm, pk.c.P)
	lm.Sub(lm, p1x)
	lm.Sub(lm, q1x)
	lm.Mod(lm, pk.c.P)
	if lm.Cmp(zero) < 0 {
		lm.Add(lm, pk.c.P)
	}
	lm.Mod(lm, pk.c.Q)
	return lm.Cmp(r) == 0, nil
}
