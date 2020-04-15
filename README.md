# CVE-2019-14040

Proof-of-concept code for CVE-2019-14040

More details about the vulnerability are available [in the blog post](https://blog.zimperium.com/multiple-kernel-vulnerabilities-affecting-all-qualcomm-devices).

If you have any questions, you are welcome to DM me on Twitter ([@tamir_zb](https://twitter.com/tamir_zb)).


## Build & Run

In order to build, run Android NDK's `ndk-build`.

In order to run the PoC, run the binary using the following command:

    LD_PRELOAD=libQSEEComAPI.so ./qseecom_uaf

Make sure to run it from a context where `/dev/qseecom` is accessible.

## Result

Running this on a Pixel 3 running Android 9 causes the kernel to panic. In
theory this PoC should work on other Android devices and versions without any
modifications but I have not tested it.
