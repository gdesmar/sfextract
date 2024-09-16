# sfextract

<a href="https://pypi.org/project/sfextract/#history"><img src="https://img.shields.io/pypi/v/sfextract.svg" alt="Latest Stable Release"></a>

This library tries to extract all internal files associated with Setup Factory executables. This extractor is based on [SFUnpacker](https://github.com/Puyodead1/SFUnpacker) but is meant to be fully executable on Linux.

## Installation

sfextract can be installed from pypi using pip:
```
pip install sfextract
```

## Use

By installing this library, you will be able to simply execute `sfextract` from your commandline.

If you wish to use it as an imported library instead, you can use
```python
from sfextract.main import extract

extractor = extract("file.exe", "output_folder")
print(extractor.version)
for file in extractor.files:
    print(file)
```

## Limitations

This library has the same limitations as the one it was based on. It currently only support Setup Factory 7, 8 and 9. At this moment, as opposed to SFUnpacker, this version does not support LZMA2.
