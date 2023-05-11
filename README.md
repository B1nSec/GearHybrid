# Prototypes for "Towards Tightly-coupled Hybrid Fuzzing via Excavating Input Specifications"

This repository provides the guidance and all the information needed to reproduce the experimental results reported in the paper.

## Prototypes

We implement two prototypes of our seed scheduling strategy. They are Gear-QSYM on top of QSYM, and Gear-Driller on top of Driller.

### Installation instructions of Gear-QSYM
#### Install GearAFL
Compile the program with:
```bash
$ cd /path/to/Gear-QSYM/GearAFL
$ make
```
You can start using the fuzzer without installation, but it is also possible to
install it with:
```bash
$ make install
```

When source code is *NOT* available, the fuzzer offers experimental support for
fast, on-the-fly instrumentation of black-box binaries. This is accomplished
with a version of QEMU running in the lesser-known "user space emulation" mode.

QEMU is a project separate from AFL, but you can conveniently build the
feature by doing:

```bash
$ cd qemu_mode
$ sudo apt install libtool libtool-bin libglib2.0-dev zlib1g automake bison
$ ./build_qemu_support.sh
$ cd ../
$ make
```

For additional instructions and caveats, see qemu_mode/README.qemu.

### Install the concolic executor of Gear-QSYM 
- Tested on Ubuntu 14.04 64bit and 16.04 64bit

~~~~{.sh}
# disable ptrace_scope for PIN
$ echo 0|sudo tee /proc/sys/kernel/yama/ptrace_scope

# install z3 and system deps
$ cd /path/to/Gear-QSYM/Gear-QSYM
$ ./setup.sh

# install using virtual env
$ virtualenv venv
$ source venv/bin/activate
$ pip install .
~~~~


### Run hybrid fuzzing

```bash
# require to set the following environment variables
#   GearAFL_ROOT: path to GearAFL
#   INPUT: input seed files
#   OUTPUT: output directory
#   CMDLINE: command line for a testing program (Non-instrumented)

# run GearAFL master
$ $GearAFL_ROOT/afl-fuzz -M gearafl-master -i $INPUT -o $OUTPUT -- $CMDLINE
# run GearAFL slave
$ $GearAFL_ROOT/afl-fuzz -S gearafl-slave -i $INPUT -o $OUTPUT -- $CMDLINE
# run GearQSYM
$ /path/to/Gear-QSYM/bin/run_qsym_afl.py -a gearafl-slave -o $OUTPUT -n gearqsym -- $CMDLINE
```



## Installation instructions of Gear-Driller
### Install GearAFL
Compile the program with:
```bash
$ cd /path/to/Gear-Driller/GearAFL
$ make
$ cd qemu_mode
$ sudo apt install libtool libtool-bin libglib2.0-dev zlib1g automake bison
$ ./build_qemu_support.sh
$ cd ../
$ make
```

For additional instructions and caveats, see qemu_mode/README.qemu.
### Install the concolic executor of Gear-Driller
```bash
$ sudo apt-get install build-essential gcc-multilib libtool automake autoconf bison debootstrap debian-archive-keyring libtool-bin python3-dev libffi-dev virtualenvwrapper git wget 
$ sudo apt-get install build-essential gcc-multilib libtool automake autoconf bison debootstrap debian-archive-keyring libtool-bin
$ sudo apt-get build-dep qemu

$ Install Anaconda
$ conda create -n driller python=3.8
$ conda activate driller
$ cd /path/to/GearDriller/angr-master
$ python3 setup.py install
$ pip install cle
$ pip install git+https://github.com/angr/tracer
$ cd /path/to/Gear-Driller/Gear-Driller
$ python3 setup.py install

```

### Run hybrid fuzzing
```bash
$ conda activate driller
# run GearAFL master
$ $GearAFL_ROOT/afl-fuzz -M fuzzer-master -i $INPUT -o $OUTPUT -- $GearAFL_CMDLINE
# run GearAFL slave
$ $GearAFL_ROOT/afl-fuzz -S fuzzer-slave -i $INPUT -o $OUTPUT -- $GearAFL_CMDLINE
# run GearDriller
$ python /path/to/Gear-Driller/run_driller.py /path/to/binary /path/to/workdir/output/fuzzer-master
```


#  datasets

We leverage two datasets in our paper. 

1. The CGC dataset. - <https://github.com/trailofbits/cb-multios>
   The initial seeds are provided by the CGC dataset.

2. The UniFuzz dataset. <https://github.com/unifuzz/overview>
   The initial seeds are provided by the UniFuzz dataset.


