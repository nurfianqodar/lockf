# LOCKF

Secure, lightweight, fast file locker for linux

## Usage

### Basic

```bash
lockf encrypt|decrypt --input path/to/input/file --output path/to/output/file --password yourpassword
```

```bash
lockf e|d -i path/to/input/file -o path/to/output/file -P yourpassword
```
### Advanced

You can set parameter for deriving password with these options
- `-t` or `--time`: time cost (default 4)
- `-m` or `--memory`: memory cost in bytes (default 131072) 
- `-p` or `--parallelism`: parallelism (default 4)


## Installation

This command will install binary at `/usr/local/bin`:

```bash
# build
make

# install
sudo make install
```
Or you can set the prefix

```bash
# build
make

# install at /home/<user>/.local/bin
sudo make install PREFIX=/home/<user>/.local
```

### Dependencies

1. openssl
2. argon2

> note: This program is using glibc
