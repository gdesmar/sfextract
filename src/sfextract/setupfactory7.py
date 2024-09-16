import os
import struct
import zlib
from io import BytesIO
from pathlib import PureWindowsPath

import pefile

from sfextract import COMPRESSION, SCRIPT_FILE_NAME, SetupFactoryExtractor, SFFileEntry, get_decompressor, xor_two_bytes

SIGNATURE = b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7"

FILENAME_EMBEDDED_INSTALLER = "irsetup.exe"
FILENAME_SIZE = 260


def valid_signature(overlay):
    first_bytes = b"".join(struct.unpack("c" * len(SIGNATURE), overlay.read(len(SIGNATURE))))
    overlay.seek(-len(SIGNATURE), os.SEEK_CUR)
    return first_bytes == SIGNATURE


def get_extractor(pe: pefile):
    overlay = BytesIO(pe.get_overlay())

    if valid_signature(overlay):
        # In version 7 after signature there is XOR-ed irsetup.exe, so next number would be file size
        # In versions 5/6 it is number of files - small number
        overlay.seek(len(SIGNATURE), os.SEEK_CUR)
        num_files = struct.unpack("I", overlay.read(4))[0]
        if num_files > 100:
            overlay.seek(-4 - len(SIGNATURE), os.SEEK_CUR)
            return SetupFactory7Extractor((7,), overlay)


def SkipString(script_data: BytesIO):
    string_size = struct.unpack("B", script_data.read(1))[0]
    script_data.seek(string_size, os.SEEK_CUR)
    # This should be based on the max length in the c structure that is holding it?
    # script_data.seek(min(string_size, 1024), os.SEEK_CUR)


def ReadString(script_data: BytesIO):
    string_size = struct.unpack("B", script_data.read(1))[0]
    return script_data.read(string_size).split(b"\x00", 1)[0]
    # This should be based on the max length in the c structure that is holding it?
    # return script_data.read(min(string_size, 1024), os.SEEK_CUR).split(b"\x00", 1)[0]


def ReadSpecialFile(overlay, output_location, filename, is_xored):
    file_size = struct.unpack("I", overlay.read(4))[0]
    target_file = os.path.join(output_location, filename)
    with open(target_file, "wb") as f:
        data = overlay.read(file_size)
        if is_xored:
            xor_key = xor_two_bytes(data[:2], b"MZ")
            data = xor_two_bytes(data, xor_key)
        f.write(data)

    return SFFileEntry(
        name=filename.encode(),
        local_path=target_file,
        unpacked_size=file_size,
        packed_size=file_size,
        compression=COMPRESSION.NONE,
        is_xored=is_xored,
    )


class SetupFactory7Extractor(SetupFactoryExtractor):

    def __init__(self, version, overlay: BytesIO):
        self.version = version
        self.overlay = overlay
        self.compression = COMPRESSION.PKWARE
        self.decompressor = get_decompressor(self.compression)

    def ParseScript(self, script: SFFileEntry, output_location):
        with open(script.local_path, "rb") as f:
            decompressed_data = f.read()
        script_data = BytesIO(decompressed_data)
        file_data_index = decompressed_data.find(b"CSetupFileData")
        if file_data_index < 8:
            return

        script_data.seek(file_data_index - 8, os.SEEK_SET)
        num_entries = struct.unpack("H", script_data.read(2))[0]
        script_data.seek(4, os.SEEK_CUR)  # Skip 2 unknown uint16_t numbers, always 0xFFFF and 0x0001
        class_name_length = struct.unpack("H", script_data.read(2))[0]
        class_name = script_data.read(min(class_name_length, 127)).split(b"\x00", 1)[0]

        # Check if we have proper script
        if class_name != b"CSetupFileData":
            return

        script_data.seek(5, os.SEEK_CUR)

        for _ in range(num_entries):
            SkipString(script_data)  # Full source path
            strBaseName = ReadString(script_data)  # Base name
            SkipString(script_data)  # Source directory
            SkipString(script_data)  # Suffix
            SkipString(script_data)  # Run-time folder (usually 'Archive')
            SkipString(script_data)  # File description
            script_data.seek(2, os.SEEK_CUR)
            nDecompSize = struct.unpack("I", script_data.read(4))[0]
            origAttr = struct.unpack("B", script_data.read(1))[0]  # Attributes of the original source file
            script_data.seek(37, os.SEEK_CUR)
            strDestDir = ReadString(script_data)  # Destination directory
            script_data.seek(10, os.SEEK_CUR)
            SkipString(script_data)  # Custom shortcut location
            SkipString(script_data)  # Shortcut comment
            SkipString(script_data)  # Shortcut description
            SkipString(script_data)  # Shortcut startup arguments
            SkipString(script_data)  # Shortcut start directory
            script_data.seek(1, os.SEEK_CUR)
            SkipString(script_data)  # Icon path
            script_data.seek(8, os.SEEK_CUR)
            SkipString(script_data)  # Font reg name (if file is font)
            script_data.seek(3, os.SEEK_CUR)
            nIsCompressed = struct.unpack("B", script_data.read(1))[0]
            useOrigAttr = struct.unpack("B", script_data.read(1))[0]  # 1 - use original file attributes
            forcedAttr = struct.unpack("B", script_data.read(1))[0]  # Set this attributes if prev. value is 0

            # A little bit of black magic (not sure if it is correct way)
            script_data.seek(10, os.SEEK_CUR)
            skipVal = struct.unpack("H", script_data.read(2))[0]
            script_data.seek(skipVal * 2, os.SEEK_CUR)

            SkipString(script_data)  # Script condition
            script_data.seek(2, os.SEEK_CUR)
            SkipString(script_data)  # Install type
            SkipString(script_data)
            packageNum = struct.unpack("H", script_data.read(2))[0]
            for _ in range(packageNum):
                SkipString(script_data)  # Package name
            SkipString(script_data)  # File notes
            nCompSize = struct.unpack("I", script_data.read(4))[0]
            nCrc = struct.unpack("I", script_data.read(4))[0]
            script_data.seek(8, os.SEEK_CUR)

            target_name = os.path.join(
                *PureWindowsPath(strDestDir.decode("utf-8", errors="ignore")).parts,
                strBaseName.decode("utf-8", errors="ignore"),
            )
            target_file = os.path.join(output_location, target_name)

            self.files.append(
                SFFileEntry(
                    name=target_name.encode(),
                    local_path=target_file,
                    unpacked_size=nDecompSize,
                    packed_size=nCompSize,
                    compression=COMPRESSION.NONE if nIsCompressed == 0 else script.compression,
                    crc=nCrc,
                    attributes=origAttr if useOrigAttr else forcedAttr,
                )
            )

            compressed_data = self.overlay.read(nCompSize)
            decompressed_data = get_decompressor(self.files[-1].compression).decompress(compressed_data)
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            with open(target_file, "wb") as f:
                f.write(decompressed_data)

    def extract_files(self, output_location):
        self.overlay.seek(8, os.SEEK_CUR)
        os.makedirs(output_location, exist_ok=True)

        # Read embedded installer .exe
        # TODO: some file do not have 1 byte shift, investigate
        self.overlay.seek(1, os.SEEK_CUR)
        self.files.append(ReadSpecialFile(self.overlay, output_location, FILENAME_EMBEDDED_INSTALLER, True))
        num_files = struct.unpack("I", self.overlay.read(4))[0]

        script_files = []

        for _ in range(num_files):
            name = self.overlay.read(FILENAME_SIZE).split(b"\x00", 1)[0]
            file_size = struct.unpack("I", self.overlay.read(4))[0]
            file_crc = struct.unpack("I", self.overlay.read(4))[0]
            is_script = name == SCRIPT_FILE_NAME
            compressed_data = self.overlay.read(file_size)
            decompressed_data = self.decompressor.decompress(compressed_data)
            # CRCs are actually not validated in the original code, but we can try to validate them here
            if file_crc and file_crc != zlib.crc32(decompressed_data):
                raise Exception(f"Bad CRC checksum on {name}")
            target_file = os.path.join(output_location, name.decode("utf-8", errors="ignore"))
            with open(target_file, "wb") as f:
                f.write(decompressed_data)

            self.files.append(
                SFFileEntry(
                    name=name,
                    local_path=target_file,
                    unpacked_size=len(decompressed_data),
                    packed_size=len(compressed_data),
                    compression=self.compression,
                    crc=file_crc,
                )
            )

            if is_script:
                script_files.append(self.files[-1])

        # There should only be one, but who knows?
        for script in script_files:
            self.ParseScript(script, output_location)
