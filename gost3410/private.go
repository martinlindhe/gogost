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
	"io"
	"math/big"
)

type PrivateKey struct {
	c   *Curve
	ds  int
	key *big.Int
}

func NewPrivateKey(curve *Curve, ds DigestSize, raw []byte) (*PrivateKey, error) {
	key := make([]byte, len(raw))
	copy(key, raw)
	reverse(key)
	k := bytes2big(key)
	if k.Cmp(zero) == 0 {
		return nil, errors.New("zero private key")
	}
	return &PrivateKey{curve, int(ds), k}, nil
}

func GenPrivateKey(curve *Curve, ds DigestSize, rand io.Reader) (*PrivateKey, error) {
	raw := make([]byte, int(ds))
	if _, err := io.ReadFull(rand, raw); err != nil {
		return nil, err
	}
	return NewPrivateKey(curve, ds, raw)
}

func (pk *PrivateKey) Raw() []byte {
	raw := pad(pk.key.Bytes(), pk.ds)
	reverse(raw)
	return raw
}

func (pk *PrivateKey) PublicKey() (*PublicKey, error) {
	x, y, err := pk.c.Exp(pk.key, pk.c.Bx, pk.c.By)
	if err != nil {
		return nil, err
	}
	return &PublicKey{pk.c, pk.ds, x, y}, nil
}

func (pk *PrivateKey) SignDigest(digest []byte, rand io.Reader) ([]byte, error) {
	if len(digest) != pk.ds {
		return nil, errors.New("Invalid input digest length")
	}
	e := bytes2big(digest)
	e.Mod(e, pk.c.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}
	kRaw := make([]byte, pk.ds)
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
	k.Mod(k, pk.c.Q)
	if k.Cmp(zero) == 0 {
		goto Retry
	}
	r, _, err = pk.c.Exp(k, pk.c.Bx, pk.c.By)
	if err != nil {
		return nil, err
	}
	r.Mod(r, pk.c.Q)
	if r.Cmp(zero) == 0 {
		goto Retry
	}
	d.Mul(pk.key, r)
	k.Mul(k, e)
	s.Add(d, k)
	s.Mod(s, pk.c.Q)
	if s.Cmp(zero) == 0 {
		goto Retry
	}
	return append(pad(s.Bytes(), pk.ds), pad(r.Bytes(), pk.ds)...), nil
}
