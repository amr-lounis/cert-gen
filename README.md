# Self-Signed SSL Certificate Generator

A GUI tool for creating SSL certificates:

- Self-signed **Root CA**
- **Server certificate signed by the CA** (a cert under the self-signed cert)
- **Intermediate CA** under the Root
- **Standalone** self-signed certificate for quick testing without a CA

Pure Python (the `cryptography` library only), no `openssl` binary needed.

---

## 1. Requirements

- Python 3.10 or newer (tested on 3.11)
- Install the dependency:

```bat
pip install -r requirements.txt
```

## 2. Running the program

```bat
python cert_gui.py
```

## 3. Project structure

```
cert_core/          <- crypto logic (touch only if you develop the core)
  models.py         <- data structures (SubjectInfo, KeySpec, ...)
  keys.py           <- RSA / EC key generation
  subject.py        <- DN identity and SAN fields
  certs.py          <- x509 certificate builders
  storage.py        <- PEM file save/load
  services.py       <- ready-made workflows (issue_self_signed_ca, ...)
cert_gui.py         <- GUI layer only
build-exe.bat       <- converts the project to an exe file
requirements.txt
.gitignore          <- generated keys/certs are ignored automatically
```

## 4. Interface overview

At the top of the window you pick one of 4 certificate types.
The form changes automatically to match your choice:

| Type         | When to use it                                                  |
|--------------|-----------------------------------------------------------------|
| Root CA      | First step: create a root CA to sign all other certs with       |
| Server cert  | A site/server certificate signed by the CA (daily use)          |
| Standalone   | Single self-signed cert without a CA (quick localhost test)     |
| Intermediate | A sub-CA signed by the Root (large setups only)                 |

### Main fields

| Field                        | Explanation                                                                                          |
|------------------------------|------------------------------------------------------------------------------------------------------|
| Common Name (CN)             | The most important field. For a server use the domain (e.g. `example.com`), for a CA use a name (e.g. `My Root CA`) |
| Organization                 | Organization name (optional)                                                                         |
| File name                    | Output file names without extension                                                                  |
| CA certificate / CA key      | Shown only for `Server cert` and `Intermediate`: pick your `ca.crt` and `ca.key` with Browse          |
| SAN DNS                      | Extra domain names, comma separated (e.g. `example.com, www.example.com`). Browsers ignore the CN when no SAN exists, so it is auto-filled from the CN if left empty |
| SAN IP                       | IP addresses, comma separated (e.g. `192.168.1.10, 127.0.0.1`)                                        |
| Validity                     | Lifetime: 1 year (825 days = browser limit), 2 years, 5 years, 10 years for a CA                      |
| Key                          | `RSA 2048` for general use, `RSA 4096` for stronger, `EC P-256` for faster and modern                 |
| Output folder                | Where files are saved (default `certs`)                                                              |

### Advanced fields (hidden by default)

Enable `Show advanced fields` to reveal: country code `C` (default SA), state,
city, unit `OU`, email, private-key password, and the CA key password if it is encrypted.

## 5. Detailed workflow

### Step 1: Create the Root CA (once)

1. Select type **Root CA**.
2. Fill in `CN`, e.g. `My Root CA`, and the organization.
3. Keep validity `10 years` and key `RSA 2048`.
4. Pick the output folder and file name `ca`.
5. Click **Generate Root CA**.

Output:

```
certs/ca.key   <- private key (secret! never share it)
certs/ca.crt   <- CA certificate (distributed to machines to trust it)
```

### Step 2: Issue a server certificate signed by the CA

1. Select type **Server cert**.
2. In the `Issuer CA` section pick the `ca.crt` and `ca.key` from step 1.
3. Set `CN` to the domain (e.g. `example.com`).
4. In `SAN DNS` list every name the server will serve: `example.com, www.example.com`.
5. If the server is also reached by IP, add it under `SAN IP`.
6. Click **Generate server certificate**.

Output:

```
certs/server.key         <- server private key
certs/server.crt         <- server certificate (installed on the server)
certs/server.chain.crt   <- chain (server cert + CA) for servers that need it
```

### Certificate for local testing (no CA)

1. Select type **Standalone**.
2. Set `CN` = `localhost`, `SAN DNS` = `localhost`, `SAN IP` = `127.0.0.1`.
3. Click **Generate standalone certificate**.

### Intermediate CA (optional)

1. Select type **Intermediate**.
2. Pick the **Root** certificate and key.
3. Set `CN`, e.g. `My Intermediate CA`.
4. After generation, issue server certificates from the Intermediate instead of the Root (pick the Intermediate files in the `Issuer CA` section).

## 6. Making browsers trust the certificates (important)

A certificate signed by your own CA shows as "not secure" until you install
the **`ca.crt`** file into the trusted store of the machine (once per machine):

**GUI method:**

1. Double-click `ca.crt` -> `Install Certificate`.
2. Choose `Local Machine` -> `Place all certificates in the following store`.
3. Choose `Trusted Root Certification Authorities` -> `Finish`.
4. Restart the browser.

**Command line (PowerShell as administrator):**

```powershell
Import-Certificate -FilePath .\certs\ca.crt -CertStoreLocation Cert:\LocalMachine\Root
```

> Note: install only `ca.crt`, never install `.key` files anywhere public.

## 7. Quick test with a Python HTTPS server

```python
import http.server, ssl

server = http.server.HTTPServer(("localhost", 4443), http.server.SimpleHTTPRequestHandler)
server.socket = ssl.wrap_socket(
    server.socket,
    keyfile="certs/localhost.key",
    certfile="certs/localhost.crt",
    server_side=True,
)
print("Serving on https://localhost:4443")
server.serve_forever()
```

Then open `https://localhost:4443` in the browser (after installing the CA
as in section 6 you will see the secure lock).

## 8. Converting the project to an exe

Double-click `build-exe.bat` (installs `pyinstaller` automatically and builds
`dist\SSLCertGen.exe` - a windowed GUI build with no black console).

## 9. Helper buttons in the interface

- **Open folder**: opens the current output folder.
- **Inspect .crt**: shows info of any certificate (Subject / Issuer / dates / SAN).
- The status line at the bottom shows the result of the last operation.

## 10. Troubleshooting

| Problem                                              | Fix                                                                  |
|------------------------------------------------------|----------------------------------------------------------------------|
| `CN field is required`                               | The CN field is mandatory - fill it in                               |
| `Select the issuer CA certificate and key`           | With `Server cert` you must pick `ca.crt` and `ca.key` first via Browse |
| Browser says "not secure" despite CA signature       | Install `ca.crt` into `Trusted Root` (section 6) and restart the browser |
| `Your connection is not private` on a subdomain      | Add the domain to `SAN DNS` and re-issue the certificate             |
| Forgot the key password                              | It cannot be recovered - create a new certificate                    |

## 11. Security notes

- `.key` files are **secret**: never email them or push them to git (`.gitignore` ignores them automatically).
- This tool is for internal environments, development and testing - it is not
  a replacement for public-authority certificates (e.g. Let's Encrypt) for
  internet-facing sites.
