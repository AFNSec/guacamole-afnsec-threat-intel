# AFNSec Guacamole Reputation Extension

The AFNSec Intel Reputation Extension adds real time IP reputation checks and optional GEO policy enforcement to Apache Guacamole.  
It allows Guacamole to call the AFNSec Threat Intelligence API during authentication and block sign ins from malicious or suspicious sources.

This extension provides a simple, API driven layer of protection against credential stuffing, brute force attempts, and abusive remote access behavior.

## Features

• Real time IP reputation lookup from the AFNSec API  
• Optional continent and country based GEO blocking  
• Optional hashed password reputation check using AFNSec honeypot data  
• AFNSec styled block screen when a sign in is denied  
• Simple configuration through guacamole.properties  
• Compatible with Apache Guacamole 1.5.x to 1.6.x  
• No local scoring logic. All verdicts come from AFNSec

## How it works

During authentication, the extension:

1. Reads the user’s source IP  
2. Queries the AFNSec Intel API  
3. Applies the configured policy (reputation or GEO)  
4. Allows or blocks the login based on the verdict  

No sensitive data or credentials are stored or transmitted.

## Installation

### 1. Download the extension

Download the prebuilt extension JAR from the Releases page:

guacamole-afnsec-threat-intel.jar


### 2. Install the extension

Copy the JAR into:



/etc/guacamole/extensions/


### 3. Configure Guacamole

Add the required AFNSec settings to guacamole.properties:

```properties
afnsec.intel.api_key=YOUR_API_KEY
afnsec.intel.api_url=https://api.afnsec.com/api/v1
afnsec.intel.mode=reputation
afnsec.geo.mode=off


A full example is included in this repository:

guacamole.properties.example

4. Restart services
sudo systemctl restart guacd
sudo systemctl restart tomcat9

Configuration options
Property	Description
afnsec.intel.api_key	Your AFNSec API key (required)
afnsec.intel.api_url	AFNSec API endpoint
afnsec.intel.mode	reputation, geo, or both
afnsec.geo.mode	off, allow, or deny
afnsec.geo.countries	Comma separated list of ISO country codes

Password reputation checks are optional and only used when configured.

Block screen

When a login is denied, Guacamole shows an AFNSec styled notification that includes:

• Client IP
• Reason for denial
• Request ID
• Timestamp

The UI reveals no sensitive internal information.

Development

The extension is written using:

• Java 11+
• Apache Maven
• Guacamole extension APIs

Source code lives in:

src/main/java/com/afnsec/intel

License

See the LICENSE file included in this repository.

About AFNSec

AFNSec provides global IP reputation, OSINT correlation, and enforcement integrations for securing authentication flows and public facing systems.

More information: https://intel.afnsec.com

