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
	"bytes"
	"crypto/rand"
	"testing"
	"testing/quick"
)

func TestRFCVectors(t *testing.T) {
	priv := []byte{
		0x28, 0x3b, 0xec, 0x91, 0x98, 0xce, 0x19, 0x1d,
		0xee, 0x7e, 0x39, 0x49, 0x1f, 0x96, 0x60, 0x1b,
		0xc1, 0x72, 0x9a, 0xd3, 0x9d, 0x35, 0xed, 0x10,
		0xbe, 0xb9, 0x9b, 0x78, 0xde, 0x9a, 0x92, 0x7a,
	}
	pubX := []byte{
		0x0b, 0xd8, 0x6f, 0xe5, 0xd8, 0xdb, 0x89, 0x66,
		0x8f, 0x78, 0x9b, 0x4e, 0x1d, 0xba, 0x85, 0x85,
		0xc5, 0x50, 0x8b, 0x45, 0xec, 0x5b, 0x59, 0xd8,
		0x90, 0x6d, 0xdb, 0x70, 0xe2, 0x49, 0x2b, 0x7f,
	}
	pubY := []byte{
		0xda, 0x77, 0xff, 0x87, 0x1a, 0x10, 0xfb, 0xdf,
		0x27, 0x66, 0xd2, 0x93, 0xc5, 0xd1, 0x64, 0xaf,
		0xbb, 0x3c, 0x7b, 0x97, 0x3a, 0x41, 0xc8, 0x85,
		0xd1, 0x1d, 0x70, 0xd6, 0x89, 0xb4, 0xf1, 0x26,
	}
	digest := []byte{
		0x2d, 0xfb, 0xc1, 0xb3, 0x72, 0xd8, 0x9a, 0x11,
		0x88, 0xc0, 0x9c, 0x52, 0xe0, 0xee, 0xc6, 0x1f,
		0xce, 0x52, 0x03, 0x2a, 0xb1, 0x02, 0x2e, 0x8e,
		0x67, 0xec, 0xe6, 0x67, 0x2b, 0x04, 0x3e, 0xe5,
	}
	signature := []byte{
		0x01, 0x45, 0x6c, 0x64, 0xba, 0x46, 0x42, 0xa1,
		0x65, 0x3c, 0x23, 0x5a, 0x98, 0xa6, 0x02, 0x49,
		0xbc, 0xd6, 0xd3, 0xf7, 0x46, 0xb6, 0x31, 0xdf,
		0x92, 0x80, 0x14, 0xf6, 0xc5, 0xbf, 0x9c, 0x40,
		0x41, 0xaa, 0x28, 0xd2, 0xf1, 0xab, 0x14, 0x82,
		0x80, 0xcd, 0x9e, 0xd5, 0x6f, 0xed, 0xa4, 0x19,
		0x74, 0x05, 0x35, 0x54, 0xa4, 0x27, 0x67, 0xb8,
		0x3a, 0xd0, 0x43, 0xfd, 0x39, 0xdc, 0x04, 0x93,
	}

	c, err := NewCurveFromParams(CurveParamsGostR34102001Test)
	if err != nil {
		t.FailNow()
	}
	prv, err := NewPrivateKey(c, DigestSize2001, priv)
	if err != nil {
		t.FailNow()
	}
	pub, err := prv.PublicKey()
	if err != nil {
		t.FailNow()
	}
	if bytes.Compare(pub.Raw()[:32], pubX) != 0 {
		t.FailNow()
	}
	if bytes.Compare(pub.Raw()[32:], pubY) != 0 {
		t.FailNow()
	}
	ourSign, err := prv.SignDigest(digest, rand.Reader)
	if err != nil {
		t.FailNow()
	}
	valid, err := pub.VerifyDigest(digest, ourSign)
	if err != nil || !valid {
		t.FailNow()
	}
	valid, err = pub.VerifyDigest(digest, signature)
	if err != nil || !valid {
		t.FailNow()
	}
}

func TestRandom2001(t *testing.T) {
	c, _ := NewCurveFromParams(CurveParamsGostR34102001Test)
	f := func(data [31]byte, digest [32]byte) bool {
		prv, err := NewPrivateKey(
			c,
			DigestSize2001,
			append([]byte{0xde}, data[:]...),
		)
		if err != nil {
			return false
		}
		pub, err := prv.PublicKey()
		if err != nil {
			return false
		}
		pubRaw := pub.Raw()
		pub, err = NewPublicKey(c, DigestSize2001, pubRaw)
		if err != nil {
			return false
		}
		sign, err := prv.SignDigest(digest[:], rand.Reader)
		if err != nil {
			return false
		}
		valid, err := pub.VerifyDigest(digest[:], sign)
		if err != nil {
			return false
		}
		return valid
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func BenchmarkSign2001(b *testing.B) {
	c, _ := NewCurveFromParams(CurveParamsGostR34102001Test)
	prv, err := GenPrivateKey(c, DigestSize2001, rand.Reader)
	if err != nil {
		b.FailNow()
	}
	digest := make([]byte, 32)
	rand.Read(digest)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prv.SignDigest(digest, rand.Reader)
	}
}

func BenchmarkVerify2001(b *testing.B) {
	c, _ := NewCurveFromParams(CurveParamsGostR34102001Test)
	prv, err := GenPrivateKey(c, DigestSize2001, rand.Reader)
	if err != nil {
		b.FailNow()
	}
	digest := make([]byte, 32)
	rand.Read(digest)
	sign, err := prv.SignDigest(digest, rand.Reader)
	if err != nil {
		b.FailNow()
	}
	pub, err := prv.PublicKey()
	if err != nil {
		b.FailNow()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pub.VerifyDigest(digest, sign)
	}
}
