# Android HTTPS Traffic Interception and SSL Pinning Bypass — Frida and Burp Suite

**Target:** `jakhar.aseem.diva` / `com.android.chrome`
**Device:** Android Emulator 5554
**CPU Architecture:** x86
**Frida Version:** 17.9.1
**Burp Suite:** Community Edition v2026.4.3
**Date:** 2026-05-17

---

## Overview

This lab demonstrates two complementary techniques for intercepting HTTPS traffic from an Android application. The first part sets up Burp Suite as a man-in-the-middle proxy and installs its CA certificate on the emulator, enabling decryption of TLS traffic at the proxy level. The second part uses Frida to hook Java-layer SSL validation methods, neutralizing certificate pinning and custom TrustManager implementations that would otherwise reject the proxy's certificate.

Together, these two layers cover the full interception chain: the proxy handles traffic routing and decryption, while Frida handles any in-app resistance to untrusted certificates.

---

## Environment

| Component | Details |
|---|---|
| Host OS | Windows 11 |
| Emulator | Android Emulator x86 — API 30 |
| CPU Architecture | x86 |
| Frida Version | 17.9.1 |
| Burp Suite | Community Edition v2026.4.3 |
| Python | 3.x |
| ADB | Platform Tools (latest) |
| Proxy address | `10.0.2.2:8080` |

---

## Prerequisites

frida-server must be running on the emulator before starting. Verify the full environment:

```
frida --version
adb devices
frida-ps -Uai
```
<img width="1118" height="623" alt="Screenshot 2026-05-17 100542" src="https://github.com/user-attachments/assets/62c246d9-a59b-4e35-a854-9535fee90958" />

---

## Part 1 — Burp Suite Proxy Setup

### 1.1 Configure the Listener

Burp Suite by default listens only on `127.0.0.1:8080` — the loopback interface, which is invisible to the Android emulator. The listener must be changed to accept connections from all network interfaces.

In Burp: **Proxy → Proxy settings → Edit → Bind to address → All interfaces → OK**

The listener entry updates from `127.0.0.1:8080` to `*:8080`, confirming it now accepts emulator connections.


**Screenshot — Burp listener configured on all interfaces**
<img width="1082" height="665" alt="Screenshot 2026-05-17 112753" src="https://github.com/user-attachments/assets/b8f55107-8ad6-4d22-9165-2e2b7cd5e528" />

### 1.2 Export the CA Certificate

Burp Suite generates its own certificate authority to sign certificates for intercepted HTTPS connections. Android must be told to trust this CA.

In Burp: **Proxy → Proxy settings → Import / export CA certificate → Export → Certificate in DER format**

Save the file locally. The exported file is 986 bytes — a standard DER-encoded X.509 certificate.
<img width="619" height="584" alt="Screenshot 2026-05-17 110949" src="https://github.com/user-attachments/assets/30740d1d-dd1c-4014-8a9b-e9539b975fcd" />


### 1.3 Push the Certificate to the Emulator

```
adb push "path\to\cert" /sdcard/burp.der
adb shell mv /sdcard/burp.der /sdcard/burp.crt
```

The file must be renamed to `.crt` — the Android certificate installer only accepts that extension in the file picker.

### 1.4 Install the Certificate on the Emulator

On the emulator:

**Settings → Security → Encryption & credentials → Install a certificate → CA certificate → Install anyway → select burp.crt**

Confirmation: `CA certificate installed`

**Screenshot — CA certificate installed confirmation**
<img width="198" height="137" alt="Screenshot 2026-05-17 112037" src="https://github.com/user-attachments/assets/0dac5baa-53f0-444d-9201-4a98ad4f8fc8" />


### 1.5 Configure the Emulator Proxy

The Android Studio emulator exposes the host machine under the fixed alias `10.0.2.2`, regardless of the host's actual Wi-Fi IP. This alias is more reliable than the Wi-Fi IP.

```
adb shell settings put global http_proxy 10.0.2.2:8080
adb shell settings get global http_proxy
```

Expected output: `10.0.2.2:8080`

---
<img width="1091" height="142" alt="image" src="https://github.com/user-attachments/assets/e2379f97-862e-4190-916f-d7091cffcc9f" />

## Part 2 — Validating Proxy Traffic Capture

With the listener, certificate, and proxy all configured, open Chrome on the emulator and navigate to:

```
http://testphp.vulnweb.com
https://testphp.vulnweb.com
```

Burp Suite → **Proxy → HTTP history** shows all requests passing through the proxy, including HTTPS requests marked with a TLS checkmark. Both HTTP and HTTPS traffic from the emulator is now fully readable in Burp.

**Screenshot — Burp HTTP history showing intercepted HTTP and HTTPS traffic**
<img width="1909" height="465" alt="Screenshot 2026-05-17 112839" src="https://github.com/user-attachments/assets/e1410ffb-692f-4e70-8061-828a130a5d3f" />


### What the CA Certificate Enables

Without the Burp CA installed, HTTPS connections through the proxy fail with `NET::ERR_CERT_AUTHORITY_INVALID`. Burp terminates the TLS connection and presents its own certificate — signed by its own CA. Android rejects this because it does not recognize Burp's CA as a trusted root.

After installation, the trust chain becomes:

```
Emulator → Burp (presents certificate signed by its CA) → target server
                 |
                 Android now trusts Burp's CA
                 → TLS handshake accepted, traffic readable
```



---

## Part 3 — SSL Pinning Bypass with Frida

### 3.1 Why the CA Certificate is Not Always Enough

Installing the CA certificate handles the browser trust store. It does not handle apps that implement their own certificate validation logic. An app using SSL pinning hardcodes the expected server certificate or public key directly in its code. Even if Android's system trust store accepts Burp's certificate, the app's internal check will reject it independently.

Frida hooks these internal validation methods and forces them to accept any certificate, including Burp's.

### 3.2 Detection Vectors Targeted

The bypass script covers five interception points:

| Target | Layer | Action |
|---|---|---|
| `javax.net.ssl.SSLContext.init()` | Java SSL | Injects a permissive TrustManager if none is provided |
| `javax.net.ssl.X509TrustManager` | Java SSL | Overrides `checkServerTrusted` and `checkClientTrusted` on all loaded implementations |
| `com.android.org.conscrypt.TrustManagerImpl` | Conscrypt (Android 7+) | Bypasses `checkTrusted`, `verifyChain`, `checkServerTrusted` |
| `okhttp3.CertificatePinner.check()` | OkHttp | Skips certificate pin verification |
| `android.webkit.WebViewClient.onReceivedSslError()` | WebView | Calls `handler.proceed()` instead of cancelling |

### 3.3 The Bypass Script

Create `sslpin_bypass_universal.js`:

```javascript
Java.perform(function(){
  const ArrayList = Java.use('java.util.ArrayList');
  function ok(tag){ console.log('[+] SSL bypass:', tag); }

  // 1) SSLContext.init — inject permissive TrustManager if none provided
  try{
    const SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom')
      .implementation = function(km, tm, sr){
        let useTm = tm;
        try {
          if (!tm || tm.length === 0){
            const X509TM = Java.registerClass({
              name: 'com.frida.FriendlyTM',
              implements: [Java.use('javax.net.ssl.X509TrustManager')],
              methods: {
                checkClientTrusted: function(chain, authType){},
                checkServerTrusted: function(chain, authType){},
                getAcceptedIssuers: function(){ return Java.array('java.security.cert.X509Certificate', []); }
              }
            });
            const TMArr = Java.use('[Ljavax.net.ssl.TrustManager;');
            const arr = TMArr.$new(1); arr[0] = X509TM.$new(); useTm = arr;
            ok('Injected permissive TrustManager');
          }
        } catch(e){}
        return this.init(km, useTm, sr);
      };
    ok('SSLContext.init patched');
  }catch(e){ console.log('[-] SSLContext.init patch failed:', e.message); }

  // 2) Patch all loaded X509TrustManager implementations
  try{
    Java.enumerateLoadedClasses({
      onMatch: function(name){
        const low = name.toLowerCase();
        if (low.includes('trust') || low.includes('pin')){
          try{
            const K = Java.use(name);
            ['checkServerTrusted','checkClientTrusted'].forEach(m => {
              if (K[m]) K[m].overloads.forEach(ov => {
                ov.implementation = function(){ ok(name+'.'+m+' -> allow'); return null; };
              });
            });
          }catch(_){}
        }
      }, onComplete: function(){ ok('X509TrustManager patches attempted'); }
    });
  }catch(e){ console.log('[-] enumerateLoadedClasses failed:', e.message); }

  // 3) Conscrypt TrustManagerImpl (Android 7+)
  ['com.android.org.conscrypt.TrustManagerImpl','org.conscrypt.TrustManagerImpl'].forEach(cls => {
    try{
      const TMI = Java.use(cls);
      ['checkTrusted','verifyChain','checkServerTrusted'].forEach(m => {
        if (TMI[m]) TMI[m].overloads.forEach(ov => {
          ov.implementation = function(){ ok(cls+'.'+m+' -> allow');
            try { return ov.apply(this, arguments); } catch(e){ try { return ArrayList.$new(); } catch(_){ return null; } }
          };
        });
      });
      ok(cls+' patched');
    }catch(e){}
  });

  // 4) OkHttp 3/4 CertificatePinner
  try{
    const CP = Java.use('okhttp3.CertificatePinner');
    if (CP.check) CP.check.overloads.forEach(ov => {
      ov.implementation = function(){ ok('okhttp3.CertificatePinner.check skip'); return; };
    });
  }catch(e){}

  // 5) WebView SSL errors
  try{
    const WVC = Java.use('android.webkit.WebViewClient');
    if (WVC.onReceivedSslError) WVC.onReceivedSslError.implementation = function(view, handler, error){
      ok('WebView onReceivedSslError -> proceed'); handler.proceed();
    };
  }catch(e){}

  console.log('[+] Universal SSL pinning bypass installed');
});
```

### 3.4 Injection

Find the target process PID:

```
frida-ps -Uai | findstr -i chrome
frida-ps -Uai | findstr -i diva
```

Attach by PID:

```
frida -U -p <PID> -l sslpin_bypass_universal.js
```

Note: on x86 emulators with Frida 17.x, spawn mode (`-f`) may fail with `unable to locate android.os.Process.setArgV0()`. Attach mode (`-p`) is the reliable alternative.

### 3.5 Expected Console Output

```
[+] SSL bypass: SSLContext.init patched
[+] SSL bypass: X509TrustManager patches attempted
[+] SSL bypass: com.android.org.conscrypt.TrustManagerImpl patched
[+] Universal SSL pinning bypass installed
```

When the app makes an HTTPS connection, additional lines fire for each hook that intercepts a validation call:

```
[+] SSL bypass: android.net.http.X509TrustManagerExtensions.checkServerTrusted -> allow
```

**Screenshot — Frida console output with all hooks confirmed**
<img width="1641" height="614" alt="Screenshot 2026-05-17 114134" src="https://github.com/user-attachments/assets/7ada1a3d-7ac8-444c-99ed-4a91a237ffab" />

---

## Part 4 — Observed Results

### DIVA

Frida attached successfully to the DIVA process. All three hook layers confirmed active. DIVA does not make outbound HTTPS connections — it is a local vulnerability training app — so no traffic appeared in Burp from this target. The hook installation itself is the demonstrable output.

### Chrome

Frida attached to the Chrome process. All hooks confirmed active. On navigation to `https://testphp.vulnweb.com`, the `X509TrustManagerExtensions.checkServerTrusted` hook fired, confirming the bypass intercepted a live TLS validation call. Chrome's hardened native TLS stack on x86 triggered a SIGTRAP after the hook returned — this is a known limitation of hooking Chrome's renderer process on x86 emulators and does not affect the validity of the hook demonstration.

**Screenshot — Frida hook firing on Chrome HTTPS connection**
<img width="1599" height="525" alt="Screenshot 2026-05-17 114348" src="https://github.com/user-attachments/assets/09297665-fd94-43c9-a3f2-89b2856f7db6" />


---

## Part 5 — Full Interception Architecture

```
Android App
    |
    | HTTPS request
    v
Frida hooks (Java layer)
    - SSLContext.init       -> permissive TrustManager injected
    - X509TrustManager      -> checkServerTrusted returns null (allow)
    - TrustManagerImpl      -> checkTrusted bypassed
    - CertificatePinner     -> check skipped
    |
    | TLS connection (Burp CA accepted)
    v
Burp Suite proxy (10.0.2.2:8080)
    - Terminates TLS, decrypts traffic
    - Re-encrypts with its own certificate (trusted by emulator)
    - Logs full request and response in HTTP history
    |
    v
Target server (testphp.vulnweb.com)
```

---



## Part 7 — Cleanup

Remove all lab configuration before ending the session:

```
adb shell settings put global http_proxy :0
```

On the emulator: **Settings → Security → Trusted credentials → User → remove PortSwigger**

Revert Burp listener back to loopback only or close Burp entirely.

---

## References

- [OWASP Mobile Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/)
- [Frida Documentation](https://frida.re/docs/)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [testphp.vulnweb.com — Acunetix authorized training target](http://testphp.vulnweb.com)

---

## Disclaimer

This lab was conducted in a controlled environment against intentionally vulnerable and authorized applications. Do not apply these techniques to applications or devices without explicit authorization.
