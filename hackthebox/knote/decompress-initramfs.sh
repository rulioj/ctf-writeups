#!/bin/sh

mkdir initramfs
cd initramfs
cp ../initramfs.cpio .
gunzip ./initramfs.cpio
cpio -idm < ./initramfs.cpio
rm initramfs.cpio
