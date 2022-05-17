# What is this

This repository contains code to perform controlled channel
attacks against AMD SEV. You can use it, to iteratively step
through a VM's execution with page fault granularity.
In addition, it can report the retired instructions between
page faults and allows to easily access the VMs memory.

This was developed as part of the  research paper "A Systematic Look at Ciphertext Side Channels on AMD SEV-SNP".
The repo with all code for the paper is [here](https://github.com/UzL-ITS/sev-ciphertext-side-channels).
Among other things, it contains multiple helper applications that use 
this library, 

# Build

## Kernel part

1) Apply the patch `linux-kernel-modifications.patch` against the [AMD SEV-SNP Linux kernel repo](https://github.com/AMDESE/AMDSEV/tree/sev-snp-devel) branch `sev-snp-part2-rfc4` at commit `c1f51e5d9156252cb296630323a7a5608c20edfd`
2) Build the kernel (e.g. using the `my-make-kernel.sh` script from the patch
3) Install the kernel on the host

The kernel patch currently only supports one running VM with one vCPU.
To setup a SEV VM, you can follow the descriptions in the AMD repo.
To avoid version incompatibilities, use the same kernel version as here,
the qemu branch `sev-snp-devel` and the ovmf branch `sev-snp-rfc-5`
(see `stable-commits` file in AMD repo).
However, this library also works against a plain VM, without any SEV
specific Kernel, Qemu or OVMF version

# Use
The kernel patch, exposes an ioctl based API that can be used by 
any userspace application. The file `c_definitions.h` contains
the definition of the ioctls and argument structs as well as
documentation on how to use them.

The go code in this repo is just a wrapper around this ioctl
api. This simply exists because I was more
comfortable to build the (lengthy) attack tools
used in the paper in Go instead of C.

The Kernel part will print some status information to dmesg
which can be helpful for debugging.
