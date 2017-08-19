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
	"bytes"
	"encoding/hex"
	"testing"
	"testing/quick"
)

func TestVKO2001(t *testing.T) {
	c, _ := NewCurveFromParams(CurveParamsGostR34102001Test)
	ukmRaw, _ := hex.DecodeString("5172be25f852a233")
	ukm := NewUKM(ukmRaw)
	prvRaw1, _ := hex.DecodeString("1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928")
	prvRaw2, _ := hex.DecodeString("5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473")
	kek, _ := hex.DecodeString("ee4618a0dbb10cb31777b4b86a53d9e7ef6cb3e400101410f0c0f2af46c494a6")
	prv1, _ := NewPrivateKey(c, Mode2001, prvRaw1)
	prv2, _ := NewPrivateKey(c, Mode2001, prvRaw2)
	pub1, _ := prv1.PublicKey()
	pub2, _ := prv2.PublicKey()
	kek1, _ := prv1.KEK2001(pub2, ukm)
	kek2, _ := prv2.KEK2001(pub1, ukm)
	if bytes.Compare(kek1, kek2) != 0 {
		t.FailNow()
	}
	if bytes.Compare(kek1, kek) != 0 {
		t.FailNow()
	}
}

func TestRandomVKO2001(t *testing.T) {
	c, _ := NewCurveFromParams(CurveParamsGostR34102001Test)
	f := func(prvRaw1 [32]byte, prvRaw2 [32]byte, ukmRaw [8]byte) bool {
		prv1, err := NewPrivateKey(c, Mode2001, prvRaw1[:])
		if err != nil {
			return false
		}
		prv2, err := NewPrivateKey(c, Mode2001, prvRaw2[:])
		if err != nil {
			return false
		}
		pub1, _ := prv1.PublicKey()
		pub2, _ := prv2.PublicKey()
		ukm := NewUKM(ukmRaw[:])
		kek1, _ := prv1.KEK2001(pub2, ukm)
		kek2, _ := prv2.KEK2001(pub1, ukm)
		return bytes.Compare(kek1, kek2) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
