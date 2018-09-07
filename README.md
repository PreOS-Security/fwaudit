# Firmware Audit (fwaudit)

Firmware Audit (fwaudit) is a platform firmware test utility. It runs tests and gathers diagnostic and security information about a system's firmware, dates and hashes the output for forensic and incident response purposes.

fwaudit is a front-end to multiple tools, including:

 * CHIPSEC

 * Firmware Test Suite (FWTS)

 * OS builtins such as lshw, dmidecode

## Intended Audience

The target audience are large scale enterprise:

 * System Administrators
 * DevSecOps
 * Blue Teams

## License

fwaudit is GNU/GPLv2

## Disclaimer & Cautionary Warning

As always, make sure you have backups of all of your data, including offsite/disconnected backups.

Firmware is software. But unlike the operating system and application software stored on your hard disk / SSD, you can't necessarily wipe and reinstall. Since platform firmware makes the system operate, you may render your system completely inoperable when working with firmware.

CHIPSEC has a specific warning that it not be installed / deployed on production end user systems:

https://github.com/chipsec/chipsec/blob/master/chipsec/WARNING.txt

fwaudit is for use at your own risk, and as is standard for free and open source software, there is no warranty, express or implied.

### Proceed Safely

The safest way to proceed:

 * assuming you have fleets of identical hardware, pick a single example on which to run tests by hand first

 * make sure test machines are under manufacturer warranty. If not it, it may be best to:
   * redeploy the hardware to a less sensitive application, that is physically secure
   * extend the warranty
   * replace sensitive hardware with new warrantied hardware.

 * ensure your example system has fully updated firmware from the manufacturer. While Intel recommends that manufacturers run these tests, the latest available test version may not be in-step with the deployed version of firmware you're currently using.

 * install and run fwaudit and prerequisites on a liveboot Linux thumb drive, or PXE boot image from RAM only, not in a normal end-user OS install

### Security

fwaudit currently needs to run as root, ideally via sudo. 

## Prerequisites

The current release has the following system restrictions:

 * architecture: Intel x86_64 (note: AMD systems will not work)

 * firmware: BIOS, UEFI, ACPI

 * operating systems: Debian GNU/Linux, and most derivatives

 * Python: CPython 2.7x

 * tools:

  * CHIPSEC

  * Firmware Test Suite (FWTS)

  * ACPICA tools (acpidump, acpiextract)

  * pciutils

  * usbutils

  * lshw

  * dmidecode

  * INTEL-SA-00075-Discovery-Tool

## Installing

CPython 2.7x and the other assorted OS utilities are typically preinstalled. Just in case:

$ sudo apt-get install -y python python-pip pciutils usbutils lshw dmidecode acpica-tools

Before proceeding, you may want to decide if you want Secure Boot enabled. If you build / install the CHIPSEC and FWTS kernel modules with Secure Boot, they may not work without - and vice versa.

Install CHIPSEC, following the instructions in the manual:

https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf

$ sudo apt-get install -y build-essential gcc nasm linux-headers-$(uname -r)

$ sudo pip install chipsec

Install FWTS:

$ sudo apt-get install fwts

Install INTEL-SA-00075-Discovery-Tool:

https://downloadcenter.intel.com/download/26755/INTEL-SA-00075-Detection-and-Mitigation-Tool

sudo cp INTEL-SA-00075-Discovery-Tool /usr/local/sbin/

Install INTEL-SA-00086-Detection-Tool (messy!):

mkdir sa00086
cd sa00086
tar -xvzf SA00086_Linux.tar.gz
sudo cp -r * /usr/local/sbin

Download fwaudit:

git clone https://github.com/PreOS-Security/fwaudit.git

OR:

wget https://github.com/PreOS-Security/fwaudit/archive/v0.0.4.zip

fwaudit does not currently have any packaging, or standard installation directory, so you simply run it directly from the download dir, or copy it to the location of your choice.

## Usage

The help and --list_tools options can be run without sudo:

$ ./fwaudit.py -h

Gives:

usage: fwaudit.py [-h] [-v] [-d] [--syslog] [-V] [--diags] [--list_tools]
                  [--list_profiles] [-t TOOL] [-p PROFILE]
                  [--output_dir OUTPUT_DIR]
                  [--output_mode {merged,out_first,err_first}] [-c] [--hash]

FirmWare Audit (FWAudit) is a platform firmware diagnostic tool.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Use verbose output.
  -d, --debug           Use debug output.
  --syslog              Send hashes over UNIX SysLog.
  -V, --version         Show program version, then exit.
  --diags               Show diagnostic information, then exit.
  --list_tools          Show available tools, then exit.
  --list_profiles       Show available tool profiles, then exit.
  -t TOOL, --tool TOOL  Specify <toolname> to run.
  -p PROFILE, --profile PROFILE
                        Specify <profilename> to run.
  --output_dir OUTPUT_DIR
                        Specify target directory to store generated files.
  --output_mode {merged,out_first,err_first}
                        Specify how to log tool output.
  -c, --colorize        Use colored output for interactive console.
  --hash                Generate SHA256 sidecar hash files for all files.

$ ./fwaudit.py --list_tools

Running a tool requires sudo:

$ sudo ./fwaudit.py -t lsusb

## Updates & Discussion

Development happens on Github:

https://github.com/PreOS-Security/fwaudit

which contains CHANGELOG.md 

We welcome Github Issues, and pull requests particularly for added features listed in HACKING.md

There are also announcement and discussion email lists. 

Please ensure you are running the latest version of the software, and you're aware of the latest updates on the announcement email list.

### Announcement Email List

Low traffic, important announcements only:

https://lists.preossec.com/mailman/listinfo/fwaudit-announce_lists.preossec.com

### Discussion Email List

PreOS employees are on the discussion list, and welcome your questions and suggestions:

https://lists.preossec.com/mailman/listinfo/fwaudit-discuss_lists.preossec.com

### Direct Email Feedback

<mailto:fwaudit@preossec.com>

### File and Links

* LICENSE.txt: GPLv2 License
* CONTRIBUTING.md: contributor guide, includes list of needed fixes/features.
* CHANGELOG.txt: the list of changes, by release.
* Home page: <https://preossec.com/products/fwaudit/> 
* Feedback alias: <mailto:fwaudit@preossec.com>.
* Source code: <https://github.com/PreOS_Security/fwaudit/>.
* PreOS Security Twitter: @PreOS_Security

EOF
