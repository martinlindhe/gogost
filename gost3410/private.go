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
	"io"
	"math/big"
)

type PrivateKey struct {
	c    *Curve
	mode Mode
	key  *big.Int
}

func NewPrivateKey(curve *Curve, mode Mode, raw []byte) (*PrivateKey, error) {
	if len(raw) != int(mode) {
		errors.New("Invalid private key length")
	}
	key := make([]byte, int(mode))
	copy(key, raw)
	reverse(key)
	k := bytes2big(key)
	if k.Cmp(zero) == 0 {
		return nil, errors.New("Zero private key")
	}
	return &PrivateKey{curve, mode, k}, nil
}

func GenPrivateKey(curve *Curve, mode Mode, rand io.Reader) (*PrivateKey, error) {
	raw := make([]byte, int(mode))
	if _, err := io.ReadFull(rand, raw); err != nil {
		return nil, err
	}
	return NewPrivateKey(curve, mode, raw)
}

func (prv *PrivateKey) Raw() []byte {
	raw := pad(prv.key.Bytes(), int(prv.mode))
	reverse(raw)
	return raw
}

func (prv *PrivateKey) PublicKey() (*PublicKey, error) {
	x, y, err := prv.c.Exp(prv.key, prv.c.Bx, prv.c.By)
	if err != nil {
		return nil, err
	}
	return &PublicKey{prv.c, prv.mode, x, y}, nil
}

func (prv *PrivateKey) SignDigest(digest []byte, rand io.Reader) ([]byte, error) {
	e := bytes2big(digest)
	e.Mod(e, prv.c.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}
	kRaw := make([]byte, int(prv.mode))
	var err error
	var k *big.Int
	var r *big.Int
	d := big.NewInt(0)
	s := big.NewInt(0)
Retry:
	if _, err = io.ReadFull(rand, kRaw); err != nil {
		return nil, err
	}
	k = bytes2big(kRaw)
	k.Mod(k, prv.c.Q)
	if k.Cmp(zero) == 0 {
		goto Retry
	}
	r, _, err = prv.c.Exp(k, prv.c.Bx, prv.c.By)
	if err != nil {
		return nil, err
	}
	r.Mod(r, prv.c.Q)
	if r.Cmp(zero) == 0 {
		goto Retry
	}
	d.Mul(prv.key, r)
	k.Mul(k, e)
	s.Add(d, k)
	s.Mod(s, prv.c.Q)
	if s.Cmp(zero) == 0 {
		goto Retry
	}
	return append(
		pad(s.Bytes(), int(prv.mode)),
		pad(r.Bytes(), int(prv.mode))...,
	), nil
}
