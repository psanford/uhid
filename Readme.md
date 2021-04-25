# Go uhid API

This is an API for creating user space HID devices from Go (on linux).

This library is a fork of https://chromium.googlesource.com/chromiumos/platform/tast-tests.git, with modifications to make it usable as a stand alone library.

Documentation for the underlying kernel API can be found here: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/hid/uhid.rst?id=refs/tags/v5.11


## Stability

The original API was primarily for testing. I intend to use this in non-testing scenarios, which means the API may evolve. We've already diverged from the upstream API and will not attempt to maintain compatibility with the chromiumos project.
