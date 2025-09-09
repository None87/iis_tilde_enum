# IIS Tilde 8.3 Enumeration Tool

A comprehensive Python 3 tool that exploits the **IIS tilde 8.3 enumeration vulnerability** to discover hidden files and directories on Microsoft IIS web servers.


## 🚀 Enhanced Features

This modernized version includes significant improvements over the original tool:

### Core Enhancements
- **🐍 Python 3 Compatible** - Fully upgraded with proper encoding handling
- **⚡ Multi-threading Support** - Configurable threading for faster enumeration
- **🔧 Advanced Dictionary Matching** - Integrated tildeGuess reverse-search algorithm
- **📊 Two-Phase Enumeration** - High-priority matching first, then optional extensive search
- **⏱️ Robust Timeout Handling** - Prevents hanging with configurable HTTP timeouts
- **📁 Dictionary Generation Mode** - Export wordlists for use with ffuf, feroxbuster, etc.

### New Capabilities
- **📄 Batch URL Processing** - Process multiple URLs from file input
- **🍪 Enhanced Session Support** - Custom cookies for authenticated testing  
- **🔍 Smart File Detection** - Automatic backup/variation checking
- **📚 Extensible Wordlists** - Support for custom dictionaries and extensions
- **🎯 Interactive Mode** - User prompts for extended enumeration

## 🛠️ Installation & Requirements

```bash
# Python 3.6+ required
pip3 install chardet

# Clone the repository
git clone https://github.com/None87/iis_tilde_enum
cd iis_tilde_enum
```

## 📖 Basic Usage

### Quick Start
```bash
# Basic enumeration
python3 tilde_enum.py -u http://target-server/

# Fast multi-threaded scan
python3 tilde_enum.py -u http://target-server/ -t 50 --timeout 5

# Generate dictionary for external tools
python3 tilde_enum.py -u http://target-server/ --dict-only
```

### Dictionary Generation Workflow
```bash
# Generate custom wordlist
python3 tilde_enum.py -u http://target/ --dict-only --dict-output custom_dict.txt

# Use with popular fuzzing tools
ffuf -w custom_dict.txt -u http://target/FUZZ -mc 200,204,301,302,307,401,403
feroxbuster -u http://target/ -w custom_dict.txt -x aspx,php,jsp
gobuster dir -u http://target/ -w custom_dict.txt -x aspx,php,jsp

# Pipeline directly (no intermediate files)
python3 tilde_enum.py -u http://target/ --dict-only --dict-output - | ffuf -w - -u http://target/FUZZ
```

### Batch Processing
```bash
# Create URL list
echo "http://target1.com/app/" > targets.txt
echo "http://target2.com/admin/" >> targets.txt

# Process all targets
python3 tilde_enum.py -U targets.txt --dict-only --dict-output combined_dict.txt
```

## 🔧 Command Line Options

```
usage: tilde_enum.py [-h] [-c COOKIE] [-d PATH_WORDLISTS] [-e PATH_EXTS] [-f]
                     [-g] [--tilde-guess] [--dict-only] [--dict-output DICT_OUTPUT]
                     [-o OUT_FILE] [-p PROXY] [-u URL] [-U URL_FILE] 
                     [-v VERBOSE_LEVEL] [-w WAIT] [-t THREADS] [--timeout TIMEOUT]
                     [--ignore-ext PATH_EXTS_IGNORE] [--limit-ext LIMIT_EXTENSION] 
                     [--resume RESUME_STRING]

Key Parameters:
  -u URL                Target URL to scan
  -U URL_FILE           File containing multiple URLs (one per line)  
  -d PATH               Custom wordlist file (default: wordlists/big.txt)
  -e PATH               Custom extensions file (default: wordlists/extensions.txt)
  -t THREADS            Number of threads (default: 10)
  --timeout TIMEOUT     HTTP request timeout in seconds (default: 10)
  -w SECONDS            Delay between requests to avoid detection
  -v LEVEL              Verbose level (0-2)
  
Dictionary Generation:
  --dict-only           Generate dictionary only, skip URL testing
  --dict-output FILE    Output dictionary file (default: generated_wordlist.txt, "-" for stdout)
  
Advanced Options:
  --tilde-guess         Enable tildeGuess algorithm (default: False)
  -c COOKIE             Cookie header for authenticated requests
  --limit-ext EXT       Only enumerate specific extension
  --resume STRING       Resume from specific string
  -f                    Force testing even if not vulnerable
```

## 🎯 Enumeration Workflow

### Phase 1: High-Priority Matching
- Performs tilde enumeration to discover short filenames (e.g., `login~1.asp`)
- Tests dictionary words that start with the discovered prefix
- Finds most common matches quickly (e.g., `login~1.asp` → `login.aspx`)

### Phase 2: Extended Search (Optional)
- For items not found in Phase 1, optionally uses tildeGuess algorithm
- Performs reverse-search pattern matching for comprehensive discovery
- User can choose to skip this phase to avoid lengthy scans

### Dictionary Generation Mode
- Skips live URL testing to prevent hanging
- Generates prioritized wordlists for external fuzzing tools
- High-priority matches listed first for optimal fuzzing efficiency

## 📊 Performance Examples

| Target | Threads | Timeout | Time | Results |
|--------|---------|---------|------|---------|
| Single App | 10 | 10s | ~2-5 min | Typical scan |
| Single App | 50 | 5s | ~30-60s | Fast scan |
| Multiple URLs | 20 | 10s | ~5-15 min | Batch processing |
| Dict Generation | N/A | N/A | ~10-30s | No URL testing |

## 🛡️ Security Considerations

- **Authorization Required**: Only use on systems you own or have explicit permission to test
- **Rate Limiting**: Use `-w` parameter to add delays between requests
- **Responsible Testing**: This tool performs active reconnaissance - use appropriate throttling
- **Network Impact**: High thread counts may impact server performance

## 📁 Wordlist Management

The tool includes several wordlist categories:
- `wordlists/big.txt` - Comprehensive filename dictionary
- `wordlists/small.txt` - Quick testing wordlist
- `wordlists/extensions.txt` - Common file extensions
- `wordlists/extensions_ignore.txt` - Extensions to skip

### Custom Wordlists
```bash
# Use custom wordlist
python3 tilde_enum.py -u http://target/ -d /path/to/custom/wordlist.txt

# Use technology-specific extensions
python3 tilde_enum.py -u http://target/ -e /path/to/asp_extensions.txt
```

## 🔗 Integration with Other Tools

### ffuf Integration
```bash
# Generate and use with ffuf
python3 tilde_enum.py -u http://target/ --dict-only
ffuf -w generated_wordlist.txt -u http://target/FUZZ -mc 200,204,301,302,307,401,403 -t 50
```

### feroxbuster Integration  
```bash
# Generate and use with feroxbuster
python3 tilde_enum.py -u http://target/ --dict-only
feroxbuster -u http://target/ -w generated_wordlist.txt -x aspx,php,jsp -t 50
```

### gobuster Integration
```bash
# Generate and use with gobuster
python3 tilde_enum.py -u http://target/ --dict-only
gobuster dir -u http://target/ -w generated_wordlist.txt -x aspx,php,jsp -t 50
```

## 🐛 Troubleshooting

### Common Issues
- **Hanging scans**: Use `--timeout` parameter and avoid excessive threading
- **False positives**: Adjust wordlists and use `--limit-ext` for specific extensions
- **Authentication**: Use `-c` parameter for cookie-based authentication
- **Rate limiting**: Increase `-w` delay between requests

### Performance Tuning
```bash
# Conservative (stable networks)
python3 tilde_enum.py -u http://target/ -t 10 --timeout 15 -w 0.1

# Aggressive (fast networks)  
python3 tilde_enum.py -u http://target/ -t 100 --timeout 3

# Bandwidth-limited
python3 tilde_enum.py -u http://target/ -t 5 --timeout 30 -w 1
```

## 📜 Technical Background

The IIS tilde enumeration vulnerability (CVE-2010-2731) affects Microsoft IIS servers when 8.3 filename support is enabled. The vulnerability allows attackers to:

1. Discover the existence of files/directories regardless of permissions
2. Enumerate short filename formats (e.g., `PROGRA~1` for `Program Files`)  
3. Use dictionary attacks to guess full filenames from short names

This tool automates the exploitation process and includes advanced techniques for converting short names back to full filenames using dictionary matching and reverse-search algorithms.


## 📝 License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations.

---

**Remember**: Only use this tool on systems you own or have explicit authorization to test. Unauthorized access to computer systems is illegal.
