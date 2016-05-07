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

var (
	zero *big.Int = big.NewInt(0)
	bigInt2 *big.Int = big.NewInt(2)
	bigInt3 *big.Int = big.NewInt(3)
	bigInt4 *big.Int = big.NewInt(4)
	bigInt8 *big.Int = big.NewInt(8)
)

type Curve struct {
	P *big.Int
	Q *big.Int
	A *big.Int
	B *big.Int

	// Basic point X and Y coordinates
	Bx *big.Int
	By *big.Int
}

func NewCurve(p, q, a, b, bx, by []byte) (*Curve, error) {
	c := Curve{
		P:  bytes2big(p[:]),
		Q:  bytes2big(q[:]),
		A:  bytes2big(a[:]),
		B:  bytes2big(b[:]),
		Bx: bytes2big(bx[:]),
		By: bytes2big(by[:]),
	}
	r1 := big.NewInt(0)
	r2 := big.NewInt(0)
	r1.Mul(c.By, c.By)
	r1.Mod(r1, c.P)
	r2.Mul(c.Bx, c.Bx)
	r2.Add(r2, c.A)
	r2.Mul(r2, c.Bx)
	r2.Add(r2, c.B)
	r2.Mod(r2, c.P)
	if r2.Cmp(big.NewInt(0)) == -1 {
		r2.Add(r2, c.P)
	}
	if r1.Cmp(r2) != 0 {
		return nil, errors.New("Invalid curve parameters")
	}
	return &c, nil
}

func (c *Curve) Exp(degree, xS, yS *big.Int) (*big.Int, *big.Int, error) {
	x := big.NewInt(1)
	y := big.NewInt(1)
	z := big.NewInt(0)
	lm1 := big.NewInt(0)
	lm2 := big.NewInt(0)
	lm3 := big.NewInt(0)
	lm4 := big.NewInt(0)
	lm5 := big.NewInt(0)
	lm6 := big.NewInt(0)
	lm7 := big.NewInt(0)
	i := degree.BitLen() - 1
	if i == 0 {
		return nil, nil, errors.New("Bad degree value")
	}
	for ; i >= 0; i -= 1 {
		if z.Cmp(zero) != 0 {
			lm2.Mul(x, x)
			lm2.Mod(lm2, c.P)
			lm2.Mul(lm2, bigInt3)
			lm1.Mul(z, z)
			lm1.Mul(lm1, c.A)
			lm1.Mod(lm1, c.P)
			lm1.Add(lm1, lm2)
			lm2.Mul(y, z)
			lm2.Mod(lm2, c.P)
			lm3.Mul(lm2, x)
			lm3.Mul(lm3, y)
			lm3.Mod(lm3, c.P)
			lm5.Mul(lm3, bigInt8)
			lm4.Mul(lm1, lm1)
			lm4.Mod(lm4, c.P)
			lm4.Sub(lm4, lm5)
			lm5.Mul(lm2, bigInt2)
			lm5.Mod(lm5, c.P)
			lm6.Mul(lm5, lm5)
			lm6.Mul(lm6, bigInt2)
			lm6.Mod(lm6, c.P)
			x.Mul(lm4, lm5)
			x.Mod(x, c.P)
			lm7.Mul(y, y)
			lm7.Mod(lm7, c.P)
			lm7.Mul(lm7, lm6)
			y.Mul(lm3, bigInt4)
			y.Sub(y, lm4)
			y.Mul(y, lm1)
			y.Sub(y, lm7)
			y.Mod(y, c.P)
			z.Mul(lm2, lm6)
			z.Mod(z, c.P)
			if x.Cmp(zero) < 0 {
				x.Add(x, c.P)
			}
			if y.Cmp(zero) < 0 {
				y.Add(y, c.P)
			}
			if z.Cmp(zero) < 0 {
				z.Add(z, c.P)
			}
		}
		if degree.Bit(i) == 1 {
			if z.Cmp(zero) == 0 {
				x.Add(zero, xS)
				y.Add(zero, yS)
				z = big.NewInt(1)
			} else {
				lm1.Mul(yS, z)
				lm1.Mod(lm1, c.P)
				lm1.Sub(lm1, y)
				lm3.Mul(xS, z)
				lm3.Mod(lm3, c.P)
				lm3.Sub(lm3, x)
				lm2.Mul(lm3, lm3)
				lm2.Mod(lm2, c.P)
				lm4.Mul(lm2, lm3)
				lm4.Mod(lm4, c.P)
				lm5.Mul(bigInt2, x)
				lm5.Mul(lm5, lm2)
				lm5.Mod(lm5, c.P)
				lm6.Mul(lm1, lm1)
				lm6.Mul(lm6, z)
				lm6.Mod(lm6, c.P)
				lm6.Sub(lm6, lm4)
				lm6.Sub(lm6, lm5)
				lm5.Mul(y, lm4)
				lm5.Mod(lm5, c.P)
				y.Mul(lm2, x)
				y.Sub(y, lm6)
				y.Mul(y, lm1)
				y.Sub(y, lm5)
				y.Mod(y, c.P)
				x.Mul(lm3, lm6)
				x.Mod(x, c.P)
				z.Mul(z, lm4)
				z.Mod(z, c.P)
				if x.Cmp(zero) < 0 {
					x.Add(x, c.P)
				}
				if y.Cmp(zero) < 0 {
					y.Add(y, c.P)
				}
				if z.Cmp(zero) < 0 {
					z.Add(z, c.P)
				}
			}
		}
	}
	if z.Cmp(zero) == 0 {
		return big.NewInt(-1), big.NewInt(-1), nil
	}
	lm1.ModInverse(z, c.P)
	lm2.Mul(x, lm1)
	lm2.Mod(lm2, c.P)
	lm3.Mul(y, lm1)
	lm3.Mod(lm3, c.P)
	return lm2, lm3, nil
}
