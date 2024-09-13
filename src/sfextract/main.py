import argparse
from pathlib import Path

import pefile

import sfextract.setupfactory7 as setupfactory7
import sfextract.setupfactory8 as setupfactory8
from sfextract import SetupFactoryExtractor, __version__


# Taken from https://stackoverflow.com/questions/1094841/get-a-human-readable-version-of-a-file-size
def sizeof_fmt(num, suffix="B"):
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def extract(file_path, output_location) -> SetupFactoryExtractor:
    pe = pefile.PE(file_path, fast_load=True)

    if extractor := setupfactory7.get_extractor(pe):
        extractor.extract_files(output_location)
        return extractor
    if extractor := setupfactory8.get_extractor(pe):
        extractor.extract_files(output_location)
        return extractor

    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", help="path to the executable to be extracted", type=Path)
    parser.add_argument("-o", "--output", help="location where files are written", type=Path, required=False)
    parser.add_argument("-v", "--version", action="version", version=__version__, help="prints program version")
    args = parser.parse_args()

    file_path = args.executable
    output_location = args.output

    if not output_location:
        output_location = file_path.parent / f"{file_path.name}_output"

    try:
        extractor = extract(file_path, output_location)
    except FileNotFoundError:
        print(f"Coudln't find {file_path.name}")
        return

    if extractor is None:
        print(f"Coudln't find extractor for {file_path.name}")
        return

    print(f"Extracted {len(extractor.files)} files from Setup Factory {'.'.join([str(x) for x in extractor.version])}")
    for file in extractor.files:
        print(
            (
                f" - {file.name.decode('utf-8', errors='ignore')} "
                f"({sizeof_fmt(file.packed_size)} -> {sizeof_fmt(file.unpacked_size)}), "
                f"Compression: {file.compression.name}"
            )
        )


if __name__ == "__main__":
    main()
