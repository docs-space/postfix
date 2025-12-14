#!/bin/sh
VERSION=$1
DIR_FILES=$2


#Prepare
sudo sed -i "s/Version:.*/Version: ${VERSION}/" $DIR_FILES/Pack/DEBIAN/control
sudo chmod -R 755 $DIR_FILES/Pack/DEBIAN

#Build
sudo dpkg-deb -b $DIR_FILES/Pack $DIR_FILES/Packages/r7mtaserver_${VERSION}.deb
sudo md5sum $DIR_FILES/Packages/r7mtaserver_${VERSION}.deb > $DIR_FILES/Packages/md5.txt