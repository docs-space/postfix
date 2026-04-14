#!/bin/sh
VERSION=$1
DIR_FILES=$2


#Prepare
sed -i "s/Version:.*/Version: ${VERSION}/" $DIR_FILES/Pack/DEBIAN/control
chmod -R 755 $DIR_FILES/Pack/DEBIAN
sed -i "s/Installed-Size:.*/Installed-Size: $(du -sk $DIR_FILES/Pack | cut -f1)/" $DIR_FILES/Pack/DEBIAN/control
( cd "$DIR_FILES/Pack" && rm -f DEBIAN/md5sums && find . -type f ! -path '*/DEBIAN/*' -exec md5sum {} > DEBIAN/md5sums \; )

#Build
dpkg-deb -b $DIR_FILES/Pack $DIR_FILES/Packages/r7mtaserver_${VERSION}.deb
md5sum $DIR_FILES/Packages/r7mtaserver_${VERSION}.deb > $DIR_FILES/Packages/md5.txt