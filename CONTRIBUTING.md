# fwaudit Hacker's Guide
======================

If you'd like to contribute to the project, here are some needed features.
Most of the current code needs to be updated to fix defects, or refactored
to be more Pythonic.

The current fwaudit release is 0.0.4-PRE-ALPHA.

Items planned on being addressed in the next release are marked with 'M2'.

Regarding adding new tools/profiles, please hold off until after M2.
The M1 tool code needs refactoring, to remove the tool-centric code,
moving the tool-centric data into a user-editable JSON file. Post-M2,
please, submit lots of JSON-based tool/profile patches!

## Coding style: 

A few suggestions for any developers who wish to contribute:
* This Python code may be ported to C. Please avoid advanced Python
  features such as: comprehensions, generators, lambdas, etc.
* The code needs to be ported to 3.x, but also must continue to run on 2.7x,
  since the UEFI CHIPSEC requires CPython 2.7x.

## Testing:

* Running tools on diverse, wide selection of different OEM models of
  systems, checking for unexpected failure and tool behavior, and
  model-specific arguments (eg, for flashrom or pawn, to dump a rom on
  that model of system), so that profiles can be made for that model.
* Test Hacking Team blob against CHIPSEC blacklist
* Test ThinkPwn.efi against CHIPSEC blacklist
* Proper Py.test/Nose testing
* Pass pep8, flake8, pyflake, pylint, etc. analysis tools
* Test with Python implementations other than CPython
* Test under hypervisors: QEMU, VirtualBox, Hyper-V, etc.

## Core App Features:

* Split into multiple source files
* Prep for proper PyPy packaging
  * Including proper dependency on CHIPSEC
* Watch for crashed exec tools, watchdog process, kill after timeout?
* Check if needed tool is available before running, SKIP relevent tests
* Validate user input, max buf overflow, escape/canonlize
* Fix ugly hack list/dict 'getter', use Python dictionaries properly
* Fix Exceptions, narrow scope, log all, create critical()
* Pass all flake8/pep8/pyflakes/pylint/etc analysis tool warnings
* Update comments to be Sphinx Google style-compatible
* Add venv/virtualenv support (in code? or just docs)
* Localization/globalization
* Check Python buffer limits of child process stdio
* Interactive buffering of child processes, for more responsive output
* Pass numeric status codes to syslog/eventlog, not just strings
* Signal handler and graceful cleanup if aborted
* Check for sufficient free space before running tests, and creating zip
* Address TOCTOU security for all file I/O
* Add OnError function for os.path.walk()
* Generate hashes.txt with hashes of all files, sha256sum-compatible
* Generate Python-style ASCII log file
* Generate zip of all generated files
* Generate HTML report with all post-run results and output
* Research ways to reduce privs when running non-root tools,
  chown/chmod/ACLs, ...
* Port from v2.7x to also support latest v3.x release, as well as 2.7x.
  Cannot be 3.x-only, needs to also work with 2.7x for UEFI Shell support.
* Port to Python implementations beyond CPython: MicroPython, PyPy,
   Stackless, Nuitka, IronPython, ...

## Domain-centric App Features:

* M2: Remove hardcoded tool-centric code, create user-editable tools.json
  and profiles.json! Add JSON entries for many tools and profiles
* Create per-tool help docs to help user install tool on their OS/distro
* Check if x86/X64 systems are non-Intel, avoid CHIPSEC on AMD
* Add feature to diff two datasets for changes
* Add ReST-ful JSON API to automate tool
* Generate sh/cmd/psh/nsh shellscript
* For CHIPSEC, let user specify additional external tests
* For CHIPSEC, determine IOMMU engine of current system
* For CHIPSEC, determine FW_type of current system
* Determine ACPI tables supported by current system
* Research PII issues of OSVs/OEMs/IBVs/etc implementations to avoid,
  UEFI NVRAM-auth, UEFI vars, ...

## External tools (M2-onward):

* More of CHIPSEC tools
* More of FWTS tools
* More ACPICA tools
* UEFI Forum's SCTs
* Google pawn
* [Win]FlashROM
* UEFI Firmware Parser
* UEFIDump
* Apple macOS's eficheck
* Intel/AMD microcode tools
* Microsoft HSTI tools for each implementation (Intel, AMD, Qualcomm, etc.)
* Security processor (Intel ME, AMD PSP, Apple T2, etc.) tools
* OEM/ODM/IBV/IHV vendor-centric, model-centric tools and profiles
* OSV vendor-centric (Linux, Mac, Windows, FreeBSD, UEFI Shell, etc.)
  tools and profiles
* Vendor (and third-party) detection tools from all recent HW/FW-related
  CVEs/advisories

## ARCH/OS Ports:

* AArch64
* x86
* AArch32
* OpenPOWER

## OS Packaging:

* Windows: native Win32/Win64, CygWin, WSL
* macOS: DMG of PKG, Homebrew
* Linux: Fedora, OpenSUSE, Arch, Ubuntu, Yocto
* BSD: FreeBSD, NetBSD, OpenBSD
* UEFI Shell

EOF
