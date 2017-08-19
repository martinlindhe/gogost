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

func TestVKO2012256(t *testing.T) {
	c, _ := NewCurveFromParams(CurveParamsGostR34102012TC26ParamSetA)
	ukmRaw, _ := hex.DecodeString("1d80603c8544c727")
	ukm := NewUKM(ukmRaw)
	prvRawA, _ := hex.DecodeString("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
	pubRawA, _ := hex.DecodeString("aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a")
	prvRawB, _ := hex.DecodeString("48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db")
	pubRawB, _ := hex.DecodeString("192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a65104883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")
	pubA, _ := NewPublicKey(c, Mode2012, pubRawA)
	pubB, _ := NewPublicKey(c, Mode2012, pubRawB)
	kek, _ := hex.DecodeString("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221")
	prvA, _ := NewPrivateKey(c, Mode2012, prvRawA)
	prvB, _ := NewPrivateKey(c, Mode2012, prvRawB)
	kekA, _ := prvA.KEK2012256(pubB, ukm)
	kekB, _ := prvB.KEK2012256(pubA, ukm)
	if bytes.Compare(kekA, kekB) != 0 {
		t.FailNow()
	}
	if bytes.Compare(kekA, kek) != 0 {
		t.FailNow()
	}
}

func TestRandomVKO2012256(t *testing.T) {
	c, _ := NewCurveFromParams(CurveParamsGostR34102012TC26ParamSetA)
	f := func(prvRaw1 [64]byte, prvRaw2 [64]byte, ukmRaw [8]byte) bool {
		prv1, err := NewPrivateKey(c, Mode2012, prvRaw1[:])
		if err != nil {
			return false
		}
		prv2, err := NewPrivateKey(c, Mode2012, prvRaw2[:])
		if err != nil {
			return false
		}
		pub1, _ := prv1.PublicKey()
		pub2, _ := prv2.PublicKey()
		ukm := NewUKM(ukmRaw[:])
		kek1, _ := prv1.KEK2012256(pub2, ukm)
		kek2, _ := prv2.KEK2012256(pub1, ukm)
		return bytes.Compare(kek1, kek2) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestVKO2012512(t *testing.T) {
	c, _ := NewCurveFromParams(CurveParamsGostR34102012TC26ParamSetA)
	ukmRaw, _ := hex.DecodeString("1d80603c8544c727")
	ukm := NewUKM(ukmRaw)
	prvRawA, _ := hex.DecodeString("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
	pubRawA, _ := hex.DecodeString("aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a")
	prvRawB, _ := hex.DecodeString("48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db")
	pubRawB, _ := hex.DecodeString("192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a65104883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")
	pubA, _ := NewPublicKey(c, Mode2012, pubRawA)
	pubB, _ := NewPublicKey(c, Mode2012, pubRawB)
	kek, _ := hex.DecodeString("79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf")
	prvA, _ := NewPrivateKey(c, Mode2012, prvRawA)
	prvB, _ := NewPrivateKey(c, Mode2012, prvRawB)
	kekA, _ := prvA.KEK2012512(pubB, ukm)
	kekB, _ := prvB.KEK2012512(pubA, ukm)
	if bytes.Compare(kekA, kekB) != 0 {
		t.FailNow()
	}
	if bytes.Compare(kekA, kek) != 0 {
		t.FailNow()
	}
}

func TestRandomVKO2012512(t *testing.T) {
	c, _ := NewCurveFromParams(CurveParamsGostR34102012TC26ParamSetA)
	f := func(prvRaw1 [64]byte, prvRaw2 [64]byte, ukmRaw [8]byte) bool {
		prv1, err := NewPrivateKey(c, Mode2012, prvRaw1[:])
		if err != nil {
			return false
		}
		prv2, err := NewPrivateKey(c, Mode2012, prvRaw2[:])
		if err != nil {
			return false
		}
		pub1, _ := prv1.PublicKey()
		pub2, _ := prv2.PublicKey()
		ukm := NewUKM(ukmRaw[:])
		kek1, _ := prv1.KEK2012512(pub2, ukm)
		kek2, _ := prv2.KEK2012512(pub1, ukm)
		return bytes.Compare(kek1, kek2) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
