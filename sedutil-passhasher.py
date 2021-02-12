#!/usr/bin/env python3
# - but should work in python 2.7 as well.
#
#   Copyright 2019 Michal Gawlik
#   SPDX-License-Identifier: Apache-2.0
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

"""
Script which prepares hashed password file for sed-opal-unlocker.

Compatible with sedutil-cli password hashing, allows using sed-opal-unlocker
with drive initialized without sedutil's -n option which disables hashing.
"""

import os
import sys
import getpass
import fcntl
import ctypes
import hashlib
import time
import operator


if sys.version_info[0] == 2:
    _text_type = unicode
    _input = raw_input
else:
    _text_type = str
    _input = input


def read_sata_disk_serial(dev):
    """Read hard drive model, serial and firmware version using SATA/IDE interface."""
    HDIO_GET_IDENTITY = 0x030d
    buf = ctypes.create_string_buffer(b'\x00', 512)

    with open(dev, "rb") as fd:
        ret = fcntl.ioctl(fd, HDIO_GET_IDENTITY, buf, True)

    if ret != 0:
        raise Exception("HDIO_GET_IDENTITY failed!")

    serial = buf[20:40]
    model = buf[54:94]
    fw = buf[46:54]
    return serial, model, fw


def read_nvme_disk_serial(dev):
    """Read hard drive model, serial and firmware version using NVME interface."""
    class NVMEAdminCmd(ctypes.Structure):
        _pack_ = 1
        _fields_ = [('opcode', ctypes.c_uint8),
                    ('flags', ctypes.c_uint8),
                    ('rsvd1', ctypes.c_uint16),
                    ('nsid', ctypes.c_uint32),
                    ('cdw2', ctypes.c_uint32),
                    ('cdw3', ctypes.c_uint32),
                    ('metadata', ctypes.c_uint64),
                    ('addr', ctypes.c_uint64),
                    ('metadata_len', ctypes.c_uint32),
                    ('data_len', ctypes.c_uint32),
                    ('cdw10', ctypes.c_uint32),
                    ('cdw11', ctypes.c_uint32),
                    ('cdw12', ctypes.c_uint32),
                    ('cdw13', ctypes.c_uint32),
                    ('cdw14', ctypes.c_uint32),
                    ('cdw15', ctypes.c_uint32),
                    ('timeout_ms', ctypes.c_uint32),
                    ('result', ctypes.c_uint32)]

    NVME_IOCTL_ADMIN_CMD = 0xc0484e41
    buf = ctypes.create_string_buffer(b'\x00', 4096)
    cmd = NVMEAdminCmd(opcode=0x06,  # NVME_IDENTIFY
                       addr=ctypes.addressof(buf),
                       data_len=4096,
                       cdw10=1)

    with open(dev, "rb") as fd:
        ret = fcntl.ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd, True)

    if ret != 0:
        raise Exception("NVME_IOCTL_ADMIN_CMD failed!")

    serial = buf[4:24]
    model = buf[24:64]
    fw = buf[64:72]
    return serial, model, fw


class Argon2Hasher(object):

    def __init__(self):
        import multiprocessing
        self._cost_mem = 1
        self._cost_mem = 1024
        self._parallelism = max(1, min(6, multiprocessing.cpu_count() // 2))
        self._libargon = ctypes.CDLL("libargon2.so.1")
        self._argon2id_hash_raw = self._libargon.argon2id_hash_raw
        self._argon2id_hash_raw.argtypes = [ctypes.c_uint32,  # t_cost
                                            ctypes.c_uint32,  # m_cost
                                            ctypes.c_uint32,  # parallelism
                                            ctypes.c_void_p,  # *pwd
                                            ctypes.c_size_t,  # pwdlen
                                            ctypes.c_void_p,  # *salt
                                            ctypes.c_size_t,  # saltlen
                                            ctypes.c_void_p,  # *hash (output)
                                            ctypes.c_size_t]  # hashlen

    def hash(self, pwd, salt, hashlen=32, t_cost=None, m_cost=None, parallelism=None):
        if t_cost is None:
            t_cost = self._cost_cpu
        if m_cost is None:
            m_cost = self._cost_mem
        if parallelism is None:
            parallelism = self._parallelism
        if isinstance(pwd, _text_type):
            pwd = pwd.encode('ascii')
        if isinstance(salt, _text_type):
            salt = salt.encode('ascii')
        buf = ctypes.create_string_buffer(b'\x00', hashlen)
        ret = self._argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, len(pwd),
                                      salt, len(salt), buf, hashlen)
        if ret != 0:
            raise RuntimeError("argon2id_hash_raw failed with error {}".format(ret))
        return buf.raw

    def calculate_costs(self, target_time):
        def measure():
            t1 = time.time()
            self.hash(b"test", b"1234567890")
            t2 = time.time()
            return t2 - t1
        # first, rough estimation of memory to be used, but no more than 512MB
        self._cost_cpu = 10
        self._cost_mem = 8 * 1024
        t = measure()
        assert 4 * t < target_time, "Sorry, you system is too slow to run this."
        off_ratio = t / target_time
        self._cost_mem = min(512 * 1024, int(round((self._cost_mem / 128.0) / off_ratio)) * 128)
        # second, CPU cost
        off_ratio = measure() / target_time
        new_cost = int(round(self._cost_cpu / off_ratio))
        if not (0.9 < off_ratio < 1.1) or abs(new_cost - self._cost_cpu) >= 2:
            self._cost_cpu = new_cost
            off_ratio = measure() / target_time
        # final memory adjustment
        self._cost_mem = int(round((self._cost_mem / 128.0) / off_ratio)) * 128

    def print_costs(self):
        print("Argon2id CPU cost = {} iterations".format(self._cost_cpu))
        print("Argon2id MEM cost = {} MB".format(self._cost_mem / 1024.0))
        print("Argon2id threads  = {}".format(self._parallelism))

    def get_hash_params(self):
        class Params(ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('t_cost', ctypes.c_uint32),
                        ('m_cost', ctypes.c_uint32),
                        ('parallelism', ctypes.c_uint32)]
        p = Params(t_cost=self._cost_cpu,
                   m_cost=self._cost_mem,
                   parallelism=self._parallelism)
        return bytearray(p)


def main():
    """Main module function implementing script body."""
    if len(sys.argv) not in (3, 4, 5):
        print("Usage: {} <disk_path> <output_passwordhash_file_path> [encrypt_password] [algorithm]".format(sys.argv[0]))
        print("       when encrypt_password is 1, passwordhash file will be encrypted")
        print("       by additional passphrase you'll be asked for.")
        print("")
        print("       algorithm can be one of 'sha1' (default) or 'sha512'.")
        print("       sha1 is used by the DriveTrustAlliance fork of sedutil.")
        print("       sha512 is used by the ChubbyAnt fork of sedutil.")
        return 0

    dev = sys.argv[1]
    out = sys.argv[2]
    try:
        encrypt_password = bool(int(sys.argv[3]) == 1)
    except Exception:
        encrypt_password = False

    try:
        algorithm = sys.argv[4]
    except Exception:
        algorithm = 'sha1'

    if algorithm not in ('sha1', 'sha512'):
        print("algorithm must be 'sha1' or 'sha512'")
        return 1

    # Read disk serial number which is needed to salt the password hash.
    # On the wire, the serial number is 20 byte string, out of which some store
    # the serial, and the rest is usually padded with spaces. But some drives
    # seems to use right-padding, others do left-padding. I guess there exists
    # disks with non-space padding as well... But since this padding also salts
    # the hash and tools like hdparm/smartctl cuts it, we can't count on them
    # and have to read the serial ourselves.
    print("Checking {}...".format(dev))
    try:
        if 'nvm' in dev:
            serial, model, fw = read_nvme_disk_serial(dev)
        else:
            serial, model, fw = read_sata_disk_serial(dev)
    except Exception as e:
        print("Failed to read disk serial: {!s}".format(e))
        return 1

    # print drive identification and ask kindly for the password
    print("Found {!s} with firmware {!s} and serial {!r}".format(model.decode('utf8').strip(),
                                                                 fw.decode('utf8').strip(),
                                                                 serial))

    if encrypt_password:
        ah = Argon2Hasher()
        ah.calculate_costs(0.6)
        print("Encrypted password hash will be written into {}".format(out))
        ah.print_costs()
    else:
        print("Password hash will be written into {}".format(out))

    # read disk password and hash it using the same settings sedutil-cli uses
    disk_password = getpass.getpass("Enter SED password for {} (CTRL+C to quit): ".format(dev))

    if algorithm == 'sha1':
        iterations = 75000
    else:
        # From https://github.com/ChubbyAnt/sedutil/blob/master/Common/DtaHashPwd.h
        iterations = 500000
    hashed = hashlib.pbkdf2_hmac(algorithm, disk_password.encode('utf8'), serial, iterations, 32)

    # if hash is going to be encrypted, read additional passphrase and salt
    if encrypt_password:
        unlock_passphrase = getpass.getpass("Enter passphrase for unlocking encrypted passwordhash file: ")
        verify_passphrase = getpass.getpass("Enter passphrase again for verification:                    ")
        if unlock_passphrase != verify_passphrase:
            print("Passphrases do not match.")
            return 1
        del verify_passphrase

        ans = _input("Use DMI data to generate passphrase salt?\nIf you say Y, the passphrase will work only on this system. [y/n]: ")
        while len(ans) != 1 or ans not in 'ynYN':
            ans = _input("Please enter 'y' or 'n': ")

        salt_value = os.urandom(11)
        salt_data = b"r" + salt_value
        if ans in 'Yy':
            try:
                with open('/sys/devices/virtual/dmi/id/product_serial', 'rb') as f:
                    salt_value = salt_value + f.readline(32).rstrip(b'\n')
                    salt_data = b"s" + salt_data[1:]
            except EnvironmentError:
                with open('/sys/devices/virtual/dmi/id/product_uuid', 'rb') as f:
                    salt_value = salt_value + f.readline(32).rstrip(b'\n')
                    salt_data = b"u" + salt_data[1:]

    # finally, save it to a file, with some magic number allowing
    # sed-opal-unlocker to recognize this as a binary (plain/encrypted) hash file,
    # which should be decrypted if needed and not mangled in any way.
    try:
        with open(out, 'wb') as f:
            if encrypt_password:
                f.write(b'\x00\x84\x11\xf8\xb5\xf8\x43\x88')
                f.write(ah.get_hash_params())
                f.write(salt_data)
                encr_key = ah.hash(unlock_passphrase, salt_value, hashlen=len(hashed))
                # bytearrays for py2.7 compatibility.
                f.write(bytearray(map(operator.xor, bytearray(hashed), bytearray(encr_key))))
            else:
                f.write(b'\x00\x84\x11\xf8\x9a\x0f\x30\x93')
                f.write(hashed)
    except EnvironmentError as e:
        print("Failed to write hashed password to {}: {!s}".format(out, e))
        return 1
    else:
        print("Hashed password saved! Protect that file properly (chown/chmod at least).")
        return 0


if __name__ == '__main__':
    sys.exit(main())
