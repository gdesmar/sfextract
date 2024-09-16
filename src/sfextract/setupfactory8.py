import os
import re
import struct
import zlib
from io import BytesIO
from pathlib import PureWindowsPath

import pefile

from sfextract import COMPRESSION, SCRIPT_FILE_NAME, SetupFactoryExtractor, SFFileEntry, get_decompressor, xor_two_bytes

SIGNATURE = b"\xe0\xe0\xe1\xe1\xe2\xe2\xe3\xe3\xe4\xe4\xe5\xe5\xe6\xe6\xe7\xe7"

FILENAME_EMBEDDED_INSTALLER = "irsetup.exe"
FILENAME_LUA_DLL = "lua5.1.dll"
FILENAME_SIZE = 264


def valid_signature(overlay):
    potential_signature = overlay.read(len(SIGNATURE))
    if len(potential_signature) != len(SIGNATURE):
        return False
    overlay.seek(-len(SIGNATURE), os.SEEK_CUR)
    return b"".join(struct.unpack("c" * len(SIGNATURE), potential_signature)) == SIGNATURE


def GetVersionFromManifest(manifest):
    assembly_identity_index = manifest.find(b"<assemblyIdentity")
    if assembly_identity_index == -1:
        return (-1, -1)
    version_index = manifest[assembly_identity_index:].find(b"version=")
    if version_index == -1:
        return (-1, -1)
    match = re.match(b"(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)", manifest[assembly_identity_index + version_index + 9 :])
    if match:
        return (int(match[1]), int(match[2]))
    return (-1, -1)


def GetVersionInfoData(pe: pefile):
    major_version = -1
    minor_version = -1
    product_names = []
    if not hasattr(pe, "VS_FIXEDFILEINFO"):
        pe.parse_data_directories()
    if not hasattr(pe, "VS_FIXEDFILEINFO"):
        return (major_version, minor_version, product_names)

    for fixed_file_info in pe.VS_FIXEDFILEINFO:
        if fixed_file_info.Signature == 0xFEEF04BD:
            major_version = (fixed_file_info.FileVersionMS >> 16) & 0xFFFF
            minor_version = (fixed_file_info.FileVersionMS >> 0) & 0xFFFF

    for file_info in pe.FileInfo:
        for typed_file_info in file_info:
            if typed_file_info.name != "StringFileInfo":
                continue
            for string_table in typed_file_info.StringTable:
                if b"ProductName" in string_table.entries:
                    product_names.append(string_table.entries[b"ProductName"])

    return (major_version, minor_version, product_names)


def get_manifests(pe: pefile):
    manifests = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        pe.parse_data_directories()
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return manifests

    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if res_type.struct.Id != 24:  # RT_MANIFEST
            continue
        if not hasattr(res_type, "directory"):
            continue
        for resource_id in res_type.directory.entries:
            if not hasattr(resource_id, "directory"):
                continue
            for resource_lang in resource_id.directory.entries:
                if not hasattr(resource_lang, "data"):
                    continue
                manifests.append(pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size))
    return manifests


def get_version(pe: pefile):
    check_bogus_manifest = False
    manifests = get_manifests(pe)
    for manifest in manifests:
        if b"<description>Setup Factory 8.0 Run-time</description>" in manifest:
            return (8, 0)

        # For SF >= 9.5
        if (
            b"<description>Setup Factory 9 Run-time</description>" in manifest
            or b"<description>Setup Factory Run-time</description>" in manifest
        ):
            major_version, minor_version = GetVersionFromManifest(manifest)
            if major_version == 9:
                return (major_version, minor_version)
            return (-1, -1)

        # Some files have bogus manifest. Let's try VersionInfo data for them
        if b"<description>Setup</description>" in manifest:
            check_bogus_manifest = True

    if check_bogus_manifest:
        major_version, minor_version, product_names = GetVersionInfoData(pe)
        if major_version == 9 and any(product_name == b"Setup Factory Runtime" for product_name in product_names):
            return (major_version, minor_version)

    return (-1, -1)


def get_extractor(pe: pefile):
    overlay = BytesIO(pe.get_overlay())

    if valid_signature(overlay):
        version = get_version(pe)
        if version[0] != -1 and version[1] != -1:
            return SetupFactory8Extractor(version, overlay)


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


def DetectCompression(overlay: BytesIO):
    buf = struct.unpack("BB", overlay.read(2))
    if buf[0] == 0x00 and buf[1] == 0x06:
        overlay.seek(-2, os.SEEK_CUR)
        return COMPRESSION.PKWARE
    elif buf[0] == 0x5D and buf[1] == 0x00:
        overlay.seek(-2, os.SEEK_CUR)
        return COMPRESSION.LZMA
    elif buf[0] == 0x18:
        overlay.seek(-2, os.SEEK_CUR)
        return COMPRESSION.LZMA2
    raise Exception("No compression found")


def ReadSpecialFile(overlay, output_location, filename, is_xored):
    file_size = struct.unpack("q", overlay.read(8))[0]
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


class SetupFactory8Extractor(SetupFactoryExtractor):

    def __init__(self, version, overlay: BytesIO):
        self.version = version
        self.overlay = overlay

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
            nDecompSize = struct.unpack("q", script_data.read(8))[0]
            origAttr = struct.unpack("B", script_data.read(1))[0]  # Attributes of the original source file
            script_data.seek(4, os.SEEK_CUR)
            createTime = struct.unpack("q", script_data.read(8))[0]
            script_data.seek(16, os.SEEK_CUR)
            modTime = struct.unpack("q", script_data.read(8))[0]
            script_data.seek(25, os.SEEK_CUR)
            strDestDir = ReadString(script_data)  # Destination directory
            if self.version[0] == 9 and self.version[1] >= 3:  # From version 9.3 script format slightly changed
                script_data.seek(11, os.SEEK_CUR)
            else:
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
            nCompSize = struct.unpack("q", script_data.read(8))[0]
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
                    last_write_time=modTime,
                    creation_time=createTime,
                )
            )

            compressed_data = self.overlay.read(nCompSize)
            decompressed_data = get_decompressor(self.files[-1].compression).decompress(compressed_data)
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            with open(target_file, "wb") as f:
                f.write(decompressed_data)

    def extract_files(self, output_location):
        self.overlay.seek(26, os.SEEK_CUR)
        os.makedirs(output_location, exist_ok=True)
        self.files.append(ReadSpecialFile(self.overlay, output_location, FILENAME_EMBEDDED_INSTALLER, True))
        num_files = struct.unpack("I", self.overlay.read(4))[0]

        # Check if this looks like real file number of we have Lua DLL file
        if num_files > 1000:
            self.overlay.seek(-4, os.SEEK_CUR)
            self.files.append(ReadSpecialFile(self.overlay, output_location, FILENAME_LUA_DLL, False))
            num_files = struct.unpack("I", self.overlay.read(4))[0]

        script_files = []

        for _ in range(num_files):
            name = self.overlay.read(FILENAME_SIZE).split(b"\x00", 1)[0]
            file_size = struct.unpack("q", self.overlay.read(8))[0]
            file_crc = struct.unpack("I", self.overlay.read(4))[0]
            self.overlay.seek(4, os.SEEK_CUR)
            is_script = name == SCRIPT_FILE_NAME
            compression = DetectCompression(self.overlay)
            compressed_data = self.overlay.read(file_size)
            decompressed_data = get_decompressor(compression).decompress(compressed_data)
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
                    compression=compression,
                    crc=file_crc,
                )
            )

            if is_script:
                script_files.append(self.files[-1])

        # There should only be one, but who knows?
        for script in script_files:
            self.ParseScript(script, output_location)
