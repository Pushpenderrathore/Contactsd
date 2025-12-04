# Contactsd

Contactsd is a secure contacts management tool designed to function on both Linux and Windows platforms. It utilizes OpenSSL libraries for cryptographic operations and provides enhanced data protection by supporting encrypted disk images.

---

## Usage on Linux

To compile and run Contactsd on Linux:

```bash
gcc contacts.c -o contactsd -lssl -lcrypto
./contactsd
```

---

## Usage on Windows

To compile and run Contactsd on Windows:

```bash
gcc contacts.c -o contactsd.exe -lssl -lcrypto
./contactsd.exe
```

> Note: Ensure you have OpenSSL and GCC installed on your Windows environment. If your source file is named `test.c`, adjust the command accordingly.

---

## Working with Encrypted Images (`result.img`) **(Admin Only — Not for Public Use)**

### To Open the Encrypted Image:

```bash
sudo cryptsetup open result.img mysecure
sudo mount /dev/mapper/mysecure /mnt/secure
```

You can access secured files at `/mnt/secure`.

### To Close and Unmount:

```bash
sudo umount /mnt/secure
sudo cryptsetup close mysecure
```

---

## Security Notice & Caution

**Do not attempt to tamper with this tool or its encrypted files. Unauthorized actions may result in data loss, corruption, or irreversible damage. Always use administrative privileges responsibly and maintain secure backups.**

---

## License

Contactsd is intended for responsible and authorized use only. Please consult our organization’s security policies before deployment.
