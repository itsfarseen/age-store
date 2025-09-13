# Known Issues

## Ubuntu Argparse Bug (Ubuntu 22.02/22.04)

Ubuntu Python argparse has a bug parsing `--` separators when optional arguments follow positional arguments before `nargs="*"`.

### Issue
**Fails on Ubuntu:**
```bash
prog positional --option value -- remaining_args
```

**Works on Ubuntu:**  
```bash
prog --option value positional -- remaining_args
```

### Workaround
Place optional arguments before positional arguments when using `--` separators with `nargs="*"`.

### Reproduction Script

Save as `repro.py`:
```python
#!/usr/bin/env python3
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("env_file")
    parser.add_argument("--shell")
    parser.add_argument("args", nargs="*")
    
    args = parser.parse_args()
    print(f"Parsed args: {args}")

if __name__ == "__main__":
    main()
```

### Test Commands

**Ubuntu (fails):**
```bash
docker run --rm -it ubuntu:24.04 bash -c "
apt update && apt install -y python3 && 
python3 -c \"$(cat repro.py)\" test.env --shell bash -- -c echo hi
"
```

**Arch Linux (works):**
```bash
docker run --rm -it archlinux bash -c "
pacman -Sy --noconfirm python &&
python3 -c \"$(cat repro.py)\" test.env --shell bash -- -c echo hi  
"
```

**Alpine (works):**
```bash
docker run --rm -it alpine sh -c "
apk add python3 &&
python3 -c \"$(cat repro.py)\" test.env --shell bash -- -c echo hi
"
```