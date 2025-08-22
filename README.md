# armv5-stratum-miner

A proof-of-concept Stratum v1 CPU miner for **ARMv5** (tested on Anyka SoCs inside cheap IP cameras).  
It is extremely slow (sub-1KH/s) and not meant for profit — **educational purposes only**.

## ✨ Features
- Minimal **Stratum v1** client (subscribe, authorize, notify, submit).
- Pure C, no external dependencies.
- **Reconnection** with backoff (1s → 10s).
- Periodic **hashrate display** (every 10s).
- Cross-compiles cleanly with `arm-linux-gnueabi-gcc`.

## ⚙️ Build
On a Debian/Ubuntu host with ARM cross-compiler:

```bash
sudo apt-get install gcc-arm-linux-gnueabi
arm-linux-gnueabi-gcc -O2 -march=armv5te -marm armv5_stratum_miner.c -o miner
file miner   # should say: ELF 32-bit ARM, EABI5
````

Optionally add `-static` if you want a fully static binary (larger).

## 📦 Deploy on device

1. Copy binary (and if dynamic, required `ld-linux.so.3` + libc) to the SD or `/mnt`.
2. On the device:

   ```sh
   chmod +x /mnt/miner
   /mnt/miner <host> <port> <user.worker> <password>
   ```

If your pool only supports SSL (`stratum+ssl://`), run through a local stunnel/port-forwarder, since this client only speaks TCP.

## 📝 Example

```sh
/mnt/miner eu.ckpool.org 3333 1YourBTCAddress.worker x
```

Output:

```
[i] connected, subscribed/authorized
[stats] hashrate ~ 0.15 H/s | shares ok=0 err=0
[+] SHARE nonce=00abc123 ex2=00000002
```

## ⚠️ Disclaimer

* **Not profitable**: ARMv5 devices extremely low hashrates
* **Educational use only**: built to show how Stratum protocol works.
* No warranty. Use at your own risk.

---

✍️ Author: itrider-gh
📜 License: [MIT](LICENSE)
