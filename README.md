# Unlocksuspend
This is a Linux [Livepatch](https://www.kernel.org/doc/html/latest/livepatch/module-elf-format.html) module which overrides Kernel Lockdown to allow hibernating when the computer has Secure Boot enabled.

## Security Implications
This module is **DANGEROUS**. Do not load it without fully understanding the security implications.

The Linux kernel developers are smarter than I am. But I decided to bypass their attempts to stop me from shooting myself in the foot. *If you load this module into your kernel, you are on your own, and you deserve what happens to you.*

## Does it work?
- Tested and working on Gentoo Linux with Kernel version `6.6.35-x86_64`, systemd, and dracut.

## Instructions
- Look over the `Makefile` and change references to make module signing work (if you use it) or remove module signing if you do not use it.
- Build and install the module to `/lib/modules/$(uname -r)`
- Add the module to Dracut, by adding the line `force_drivers+=" unlocksuspend "` to `/etc/dracut.conf.d/flags.conf` and rebuilding the initrd
- Reboot
- Enjoy!
