# Dictionary Generation and Usage Examples

## Dictionary Generation Mode

### Generate Dictionary to File
```bash
# Generate dictionary for a single URL and save to file
python3 tilde_enum.py -u http://target.com/path/ --dict-only --dict-output generated_wordlist.txt

# Use custom wordlist for better matches
python3 tilde_enum.py -u http://target.com/path/ --dict-only --dict-output generated_wordlist.txt -d wordlists/big.txt

# Generate from multiple URLs
python3 tilde_enum.py -U urls.txt --dict-only --dict-output combined_wordlist.txt
```

### Generate Dictionary to stdout
```bash
# Print dictionary to terminal (useful for piping)
python3 tilde_enum.py -u http://target.com/path/ --dict-only

# Pipe directly to other tools
python3 tilde_enum.py -u http://target.com/path/ --dict-only | ffuf -w - -u http://target.com/path/FUZZ
```

## Using Generated Dictionary with Popular Tools

### ffuf (Fast web fuzzer)

#### Basic Usage
```bash
# First generate the dictionary
python3 tilde_enum.py -u http://target.com/path/ --dict-only --dict-output custom_dict.txt

# Use with ffuf
ffuf -w custom_dict.txt -u http://target.com/path/FUZZ -mc 200,204,301,302,307,401,403
```

#### Advanced ffuf Examples
```bash
# With custom headers and cookies
ffuf -w custom_dict.txt -u http://target.com/path/FUZZ \
     -H "User-Agent: Custom-Agent" \
     -H "Cookie: session=abc123" \
     -mc 200,204,301,302,307,401,403

# Multiple extension fuzzing
ffuf -w custom_dict.txt -w wordlists/extensions.txt \
     -u http://target.com/path/FUZZFUZ2Z \
     -mc 200,204,301,302,307,401,403

# With rate limiting and delay
ffuf -w custom_dict.txt -u http://target.com/path/FUZZ \
     -mc 200,204,301,302,307,401,403 \
     -rate 100 -p 0.1

# Filter by response size
ffuf -w custom_dict.txt -u http://target.com/path/FUZZ \
     -mc 200,204,301,302,307,401,403 \
     -fs 1245  # Filter out responses with size 1245 (common 404 size)
```

### feroxbuster (Fast directory/file brute forcer)

#### Basic Usage
```bash
# Generate dictionary and use with feroxbuster
python3 tilde_enum.py -u http://target.com/path/ --dict-only --dict-output custom_dict.txt

# Use with feroxbuster
feroxbuster -u http://target.com/path/ -w custom_dict.txt
```

#### Advanced feroxbuster Examples
```bash
# With custom extensions
feroxbuster -u http://target.com/path/ -w custom_dict.txt -x php,aspx,jsp,html

# With custom status codes and threads
feroxbuster -u http://target.com/path/ -w custom_dict.txt \
            -s 200,204,301,302,307,401,403 \
            -t 50

# With depth and rate limiting
feroxbuster -u http://target.com/path/ -w custom_dict.txt \
            -d 3 \
            --rate-limit 100

# With custom user agent and headers
feroxbuster -u http://target.com/path/ -w custom_dict.txt \
            -a "Custom-Agent/1.0" \
            -H "Cookie: session=abc123"

# Filter by response size
feroxbuster -u http://target.com/path/ -w custom_dict.txt \
            -S 1245  # Filter out responses with size 1245
```

### gobuster (Directory/file brute forcer)

```bash
# Generate dictionary and use with gobuster
python3 tilde_enum.py -u http://target.com/path/ --dict-only --dict-output custom_dict.txt

# Use with gobuster
gobuster dir -u http://target.com/path/ -w custom_dict.txt -x php,aspx,jsp,html

# With custom status codes and threads
gobuster dir -u http://target.com/path/ -w custom_dict.txt \
         -s "200,204,301,302,307,401,403" \
         -t 50
```

### dirb (Web Content Scanner)

```bash
# Generate dictionary and use with dirb
python3 tilde_enum.py -u http://target.com/path/ --dict-only --dict-output custom_dict.txt

# Use with dirb
dirb http://target.com/path/ custom_dict.txt

# With custom extensions
dirb http://target.com/path/ custom_dict.txt -X .php,.aspx,.jsp,.html
```

## Workflow Examples

### Complete Enumeration Workflow
```bash
# Step 1: Perform tilde enumeration and generate dictionary
python3 tilde_enum.py -u http://target.com/app/ --dict-only --dict-output app_dict.txt -d wordlists/big.txt

# Step 2: Use multiple tools for comprehensive scanning
# ffuf for fast initial scan
ffuf -w app_dict.txt -u http://target.com/app/FUZZ -mc 200,204,301,302,307,401,403 -o ffuf_results.json

# feroxbuster for recursive discovery
feroxbuster -u http://target.com/app/ -w app_dict.txt -x aspx,php,jsp -o feroxbuster_results.txt

# gobuster for additional verification
gobuster dir -u http://target.com/app/ -w app_dict.txt -x aspx,php,jsp -o gobuster_results.txt
```

### Pipeline Approach
```bash
# Direct pipeline without intermediate files
python3 tilde_enum.py -u http://target.com/app/ --dict-only | \
ffuf -w - -u http://target.com/app/FUZZ -mc 200,204,301,302,307,401,403
```

### Batch Processing
```bash
# Create URL list
echo "http://target1.com/app/" > targets.txt
echo "http://target2.com/admin/" >> targets.txt
echo "http://target3.com/portal/" >> targets.txt

# Generate combined dictionary
python3 tilde_enum.py -U targets.txt --dict-only --dict-output combined_dict.txt

# Use combined dictionary against all targets
while read url; do
    echo "Scanning: $url"
    ffuf -w combined_dict.txt -u "${url}FUZZ" -mc 200,204,301,302,307,401,403
done < targets.txt
```

## Tips and Best Practices

1. **Rate Limiting**: Always use rate limiting to avoid overwhelming the target server
2. **Status Code Filtering**: Filter for relevant status codes (200,204,301,302,307,401,403)
3. **Size Filtering**: Use `-fs` in ffuf or `-S` in feroxbuster to filter out common 404 page sizes
4. **Extension Lists**: Combine with technology-specific extension lists for better results
5. **Multiple Tools**: Use different tools for cross-validation of results
6. **Recursion**: Consider using recursive scanning with feroxbuster for deeper enumeration

## Common Issues and Solutions

### High Memory Usage
```bash
# Use streaming with smaller chunks
python3 tilde_enum.py -u http://target.com/path/ --dict-only -d wordlists/small.txt --dict-output small_dict.txt
```

### Rate Limiting
```bash
# Add delays between requests during generation
python3 tilde_enum.py -u http://target.com/path/ --dict-only -w 0.5 --dict-output dict.txt

# Use rate limiting in fuzzing tools
ffuf -w dict.txt -u http://target.com/path/FUZZ -rate 50 -p 0.2
```

### Large Target Lists
```bash
# Process targets in batches
split -l 10 large_targets.txt batch_
for batch in batch_*; do
    python3 tilde_enum.py -U "$batch" --dict-only --dict-output "${batch}_dict.txt"
done
```