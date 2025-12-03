# USAGE IN LINUX

```bash
 gcc contacts.c -o a.out -lssl -lcrypto
 ./a.out 
```
---

# USAGE IN WINDOWS

```bash
 gcc test.c -o file.exe -lssl -lcrypto
 ./file.exe
```
---

# result.img (ADMIN ONLY – NOT FOR PUBLIC USE)

Open:
sudo cryptsetup open result.img mysecure
sudo mount /dev/mapper/mysecure /mnt/secure

Files are inside:
/mnt/secure

Close:
sudo umount /mnt/secure
sudo cryptsetup close mysecure

---

# CAUTION!

Never try to Tamper This tool. It can be overwritten or Crash.
