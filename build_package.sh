#!/bin/sh
VERSION=$1
DIR_FILES=$2


#Prepare
sudo sed -i "s/Version:.*/Version: ${VERSION}/" $DIR_FILES/Pack/DEBIAN/control
sudo chmod -R 755 $DIR_FILES/Pack/DEBIAN
size_inKb=$(du -sk $DIR_FILES/Pack | cut -f1)
sudo sed -i "s/Installed-Size:.*/Installed-Size: ${size_inKb}/" $DIR_FILES/Pack/DEBIAN/control

NOWDIR=$PWD
cd $DIR_FILES/Pack
find . -type f ! -path '*/DEBIAN/*' -exec md5sum {} > DEBIAN/md5sums \;
cd $NOWDIR
#Build
sudo dpkg-deb -b $DIR_FILES/Pack $DIR_FILES/Packages/r7mtaserver_${VERSION}.deb
rm -f $DIR_FILES/Pack/DEBIAN/md5sums
sudo md5sum $DIR_FILES/Packages/r7mtaserver_${VERSION}.deb > $DIR_FILES/Packages/md5.txt