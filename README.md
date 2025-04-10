# Simple Malware Analysis Toolkit

A simplified command-line malware analysis tool that provides basic static analysis capabilities.

## Features

- Basic file information analysis (size, hashes, timestamps)
- PE file analysis (entry point, sections, imports, exports)
- YARA rule-based detection
- String extraction and analysis
- Optional VirusTotal integration
- Rich console output with formatted tables

## Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python main.py <file_path>
```

### Optional: VirusTotal Integration

To enable VirusTotal analysis, set your API key as an environment variable:
```bash
# Windows
set VIRUSTOTAL_API_KEY=your_api_key_here

# Linux/Mac
export VIRUSTOTAL_API_KEY=your_api_key_here
```

## Analysis Features

1. **File Information**
   - File size
   - MD5 and SHA256 hashes
   - File type detection
   - Creation and modification timestamps

2. **PE Analysis**
   - Entry point address
   - Number of sections
   - Import and export functions
   - Suspicious API calls detection

3. **YARA Analysis**
   - Detection of packed executables
   - Suspicious PE characteristics
   - Common malware strings

4. **String Analysis**
   - Extraction of printable strings
   - Detection of suspicious patterns
   - Network-related strings

## Example Output

The tool provides formatted output using rich tables, showing:
- File information in a structured table
- PE analysis results
- YARA rule matches
- Extracted strings
- VirusTotal results (if API key is provided)

## Requirements

- Python 3.6+
- pefile
- yara-python
- capstone
- python-magic
- rich
- requests (for VirusTotal integration)

## Security Note

This tool is for educational purposes only. Always use caution when analyzing potentially malicious files in a secure environment. 