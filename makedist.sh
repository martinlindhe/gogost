#!/bin/sh -ex

cur=$(pwd)
tmp=$(mktemp -d)
release=$1
[ -n "$release" ]

git clone . $tmp/gogost-$release
cd $tmp/gogost-$release
git checkout $release

find . -name .git -type d | xargs rm -fr
rm -f www* makedist* TODO

cd ..
tar cvf gogost-"$release".tar gogost-"$release"
xz -9 gogost-"$release".tar
gpg --detach-sign --sign --local-user 82343436696FC85A gogost-"$release".tar.xz

tarball=gogost-"$release".tar.xz
size=$(( $(wc -c < $tarball) / 1024 ))
hash=$(gpg --print-md SHA256 < $tarball)
hashsb=$($HOME/work/gogost/gogost-streebog < $tarball)

cat <<EOF
An entry for documentation:
@item $release @tab $size KiB
@tab @url{gogost-${release}.tar.xz, link} @url{gogost-${release}.tar.xz.sig, sign}
@tab @code{$hash}
@tab @code{$hashsb}
EOF

cat <<EOF
Subject: GoGOST $release release announcement

I am pleased to announce GoGOST $release release availability!

GoGOST is free software pure Go GOST cryptographic functions library.
GOST is GOvernment STandard of Russian Federation (and Soviet Union).

------------------------ >8 ------------------------

The main improvements for that release are:


------------------------ >8 ------------------------

GoGOST'es home page is: http://www.cypherpunks.ru/gogost/

Source code and its signature for that version can be found here:

    http://www.cypherpunks.ru/gogost/gogost-${release}.tar.xz ($size KiB)
    http://www.cypherpunks.ru/gogost/gogost-${release}.tar.xz.sig

Streebog-256 hash: $hashsb
SHA256 hash: $hash
GPG key ID: 0x82343436696FC85A GoGOST releases <gogost at cypherpunks dot ru>
Fingerprint: CEBD 1282 2C46 9C02 A81A  0467 8234 3436 696F C85A

Please send questions regarding the use of GoGOST, bug reports and patches
to mailing list: https://lists.cypherpunks.ru/mailman/listinfo/gost
EOF

mv $tmp/$tarball $tmp/"$tarball".sig $cur/gogost.html/
