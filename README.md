# 🛡️ AFNSec Guacamole Threat Intelligence Extension (BETA)

Official binary releases of proprietary **AFNSec** extensions for [Apache Guacamole](https://guacamole.apache.org/).  
These add advanced features and customization in Apache Guacamole.
---

## 📘 Overview

The AFNSec Intel Reputation Extension adds real time IP reputation checks and optional GEO policy enforcement to Apache Guacamole. 

It allows Guacamole to call the AFNSec Threat Intelligence API during authentication and block sign ins from malicious or suspicious sources.

This extension provides a simple, API driven layer of protection against credential stuffing, brute force attempts(honeypot hashed password only), and abusive remote access behavior.

## 📦 Current Release

| Extension | Description | Guacamole Version | Release |
|------------|--------------|------------------|----------|
| **guacamole-afnsec-threat-intel** | Provide IP reputation and Geo blocking. | 1.5+| 1.0.0 |


## Features

• Real time IP reputation lookup from the AFNSec API  
• Optional continent and country based GEO blocking  
• Optional hashed password reputation check using AFNSec honeypot data  
• AFNSec styled block screen when a sign in is denied  
• Simple configuration through guacamole.properties  
• Compatible with Apache Guacamole 1.5.x to 1.6.x  

## How it works

During authentication, the extension:

1. Reads the user’s source IP  
2. Queries the AFNSec Intel API  
3. Applies the configured policy (reputation or GEO)  
4. Allows or blocks the login based on the verdict  

No sensitive data or credentials are stored or transmitted.

## Installation

### Download the extension

Download the prebuilt extension JAR from the Releases page:

guacamole-afnsec-threat-intel.jar


#### Install the extension

Copy the JAR into:

```bash
/etc/guacamole/extensions/
```
---

### Configure Guacamole

Add the required AFNSec settings to guacamole.properties (see "guacamole.properties.example" for more):

A full example is included in this repository:

 See: [`/guacamole.properties.example](./guacamole.properties.example)

 Visit https://protal.afnsec.com to get API Key

---

### Restart services

```bash
sudo systemctl restart tomcat9
```


Note: Password reputation checks are optional and only used when configured.

Source code lives in:

src/main/java/com/afnsec/intel

## 🧾 License

This software is **free for personal and internal organizational use only**.  
Redistribution, resale, or modification are **not permitted**.

See the full [LICENSE](./LICENSE).

---

## 🧠 Support & Security

- **Email:** [info@afnsec.com](mailto:info@afnsec.com)

Please report security issues privately to the email above.

---

© 2025 **AFNSec** — All rights reserved.

