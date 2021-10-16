-10 6# Study Guide For CompTIA Security+

## 1.0 Threats, Attacks, and Vulnerabilities

### 1.1 Compare and contrast different types of social engineering techniques.

Social engineering is a form of attach that exploits human nature and human behavior. The only direct defense against social engineering attacks is user education and awareness training.

#### Phishing
Malicious SPAM.
Email containing link or attachment for user to click to retrieve sensitive personal information.
#### Smishing
SMS phishing. Attack done over standard text messaging services.
#### Vishing
Voice phishing (some automated). Done over telephone or voice communication system.
#### Spam
Unwanted advertisements. Can also contain malicious content.
#### Spam over instant messaging (SPIM)
Unwanted email over messaging
#### Spear phishing
Phishing targetted at group of user or even single user
#### Dumpster diving
Going into the trash/recycle to find information
#### Shoulder surfing
Looking over shoulder to get some info
#### Pharming
Pharming is the malicious redirection of valid website's URL or IP address to a fake website that hosts a false version of the original valid site.
#### Tailgating
Entering building using previous employee badge
#### Eliciting information
Act of getting information without asking directly for it. Casual conversation...getting pet names, favorite color, ...
Active listening
Reflective question
False statement
Bracketing: ask question about range so user gives you the good answer
#### Whaling
Spear phishing that attempts to target a high-level executives (CEO, CFO, ...)

#### Prepending
Adding [EXTERNAL] to email...careful attacker might use same tactic like prepending [SAFE] to email

#### Identity theft
Act of stealing someone's identity.
#### Identity fraud
Use personal information to commit fraud, like take a loan using false identity
#### Invoice scams
Try to trick people/organization into paying for goods or services they didn't ask for and usually didn't received.
#### Credential harvesting
Collect username and password. Simplest way is to ask for it. Phishing.
#### Reconnaissance
Gathering as must information on a target as possible.
#### Hoax
Often email asking urgent things making user do dangerous things like executing a file (hoax of will)
#### Impersonation
Pass for someone you are not. ID verification is a simple an effective way to prevent impersonation
#### Watering hole attack
Identify site where target or group of target are likely to visit and infect this site (more vulnerable). Example, if organization employee are big fans of golf, infect web site related to golf that they visit regularly.
#### Typosquatting
Domain name close to actual name ex www.gooogle.com
Reason to pay for erroneous domain:
- Hosting malicious site
- Earning ad revenue
- Reselling domain
#### Pretexting
Add context to conversation before asking real question
#### Influence campaigns
Social engineering attacks that attempt to guide, adjust, or change public opinion, often waged by nation-states against their real or perceived foreign enemies.
##### Hybrid warfare
Combine of classical military strategy with modern capabilities, including digital influence campaigns, psychological warfare efforts, political tactics, and cyber warfare capabilities. Also known as non-linear warfare.
##### Social media
Use social media to influence people.
#### Principles (reasons for effectiveness)
  ##### Authority
  Raised to respect authority
  Works best with impersonation
  Whaling -> executive respect authority such as legale
  Vishing
  ##### Intimidation
  Attackers attempts to intimidating the victim into performing an actiom
  Works best with impersonation
  ##### Consensus
  People are often more willing to do this other people do. (like comment amazon)
  ##### Scarcity
  Rare
  People are often encouraged to act when they believe there is a limited quantity.
  Effective with phishing and trojan
  ##### Familiarity
  More likely to be off guard with people you know and like.
  Attacker will attempt to establish a rapport before launching their attack.
  Shoulder surfing
  Tailgathing
  ##### Trust
  Social engineer attempt to build some trust. Takes time.
  Vishing attack often use this method.
  ##### Urgency
  People more likely to act without thinking when there a form of urgency.
  Ransomware
  Phishing
  Whaling
  Vishing



## 1.2 Given a scenario, analyze potential indicators to determine the type of attack.

### Malware
Malware or malicious code is any element of software that performs an unwanted function from the perspective of the legitimate user or owner of the computer system.
#### Viruses
Malicious code that attaches itself to a host application
Malicious code executes when the host application is executed
Virus replicate by finding other host application to infect
At some point virus activates and delivers it's payload
Payload of virus is damaging
- deletes files
- random reboot
- join PC to botnet
- enable backdoor

#### Ransomware
Malware that takes control of a user's system or user's data. Attacker's attempt to extort payment from victim. Usually encripting user data.
#### Trojans
Trojan typically looks like something beneficial but is actually malicious, will include a backdoor for example.
In PC trojan can be: - pirated software
                     - useful utility
                     - a game
Many trojan are delivered by drive-by downloads (web servers that was compromised and visiting the site will attempt to download the trojan)
Fake antivirus
#### Worms
Worms are designed to exploit a specific vulnerability in a system and then use that flaw to replicate themselves to other systems. Worms typically focus on replication and distribution, rather than on direct damage and destruction.
Consumes network bandwidth.

#### Potentially unwanted programs (PUPs)
Software including unwanted software. Sometimes legit, other time malware. Anything not malware could potential be considered as PUP.

#### Fileless virus
Malicious software reside in memory.
- Memory code injection: malware inject code into legitimate application
- Script-based technique
- Windows registry manipulation

Fileless virus can be embedded within vCard

#### Command and control (C&C)
Give instruction to bots in botnet
Now used for more then botnet
USe IRC to give bots command but easy to find.
Some attackers use P2P to host command and control.
#### Bots and Botnets
Bots are software robots
Botnets: multiple computer that act as software bots and work together as a network
Bots in botnets are often called zombies and do the work of the person controlling the botnet
Bot herders: criminal controlling the botnet
Bots check in with the command and control systems to receive their commands to execute

#### Cryptomalware
Cryptomalware is a form of malware that uses the system resources of an infected computer to mine cryptocurrencies.
#### Logic bombs
Code embedded in application or script that is triggered by an event (date/time, application launched, ...).
#### Spyware
Spyware is any form of malicious code or even business commercial code that collects information about users without their direct knowledge or permission.
Monitor's user computer and often includes a keylogger.

#### Keyloggers
A keylogger is a form of unwanted software that records the keystrokes typed into a system's keyboard.
#### Remote access Trojan (RAT)
Malware that allows attackers to control the PC from a remote location.
Delivered by: drive-by downloads or malicious attachment in emails.
Growing trend to deliver by Portable Executable (PE)
Collect and log key stroke username, password, in-out email, chat sessions, browser history, take snapshot

#### Rootkit
Use hooking technique to hide.
Have system-level/root access.
Inspectin RAM can allow to discover these hidden hooked processes.
Special type of hacker tool that embeds itself deep within an OS, where it can manipulate information seen by the OS and displayed to users.

#### Backdoor
Another way to access to a system (created by malware or by developper)
Malware install backdoor to bypass normal authentication methods.

### Password attacks
Password attacks are collectively known as password cracking or password guessing.
#### Spraying
Special brute force or dictionary attack aimed at preventing account lockout.
Uses a large list of target users. A software takes a password and tries it for each users in the list.
The time it takes to try the password on every users account it expected to be long enough to prevent account lockout.

#### Dictionary
It uses a dictionary of words and attempts every words in the dictionary to see if it works.
These attack are thwarted by using complex password.
#### Brute force
Attempt to guest all possible character combinaissons. Longer the password longer it takes.

##### Offline
Offline password attacks attempts to discover passwords from captured database or captured packet scan.

##### Online
Online password attacks attempts to discover password from online system.

#### Rainbow table
Attempt to discover the password from the hash. Rainbow table are large database of possible passwords with the precomputed hashes for each.
#### Plaintext/unencrypted

### Physical attacks
#### Malicious Universal Serial Bus (USB) cable & flash drive
A malicious universal serial bus cable or flash drive is a device crafted to perform unwanted activities against a computer and/or mobile device or peripheral without the victim realizing the attack is occuring.
Attacks include exfiltrating data and injecting malware.
#### Card cloning & Skimming
Card cloning is the duplication if data (skimming) from a targeted source card onto a blank new card.
### Adversarial artificial intelligence (AI)
Adversarial artificial intelligence (AI) (AAI) or adversarial machine learning (ML) (AML) is a training or programming technique where computational systems are set up to operate in opposition to automate the process of developing system defenses and attacks. Also called a generative adversarial network (GAN)

#### Tainted training data for machine learning (ML)
Possible to use tainted data for ML to cause AI and ML system to give inconsistent results.
#### Security of machine learning algorithms


### Supply-chain attacks
Supply chain attacks could result in flawed or less reliable products or could allow for remote access or listening mechanisms to be embedding into otherwise functioning equipment.
### Cloud-based vs. on-premises attacks
### Cryptographic attacks
#### Birthday
Exploit collisions in hashing algorithm.
#### Collision
Hash collision occurs when the hashing algorithm creates the same hash from different passwords.
#### Downgrade
A downgrade attack is a form of cyber attack in which an attacker forces a network channel to switch to an unprotected or less secure data transmission standard.
Downgrading the protocol version is one element of man-in-the-middle type attacks, and is used to intercept encrypted traffic



## 1.3 Given a scenario, analyze potential indicators associated with application attacks.
### Privilege escalation
Privilege escalation occurs when a user account is able to obtain unauthorized access to higher levels of privileges.
### Cross-site scripting
Cross-site scripting (XSS) is a form of malicious code injection attack in which an attacher is able to compromise a web server and inject their own malicious code into the content sent to other visitors.
### Injections
An injection attack is nay exploitation that allows an attacker to submit code to a target system to modify its operations and/or poison and corrupt its data set.
#### Structured query language (SQL)
SQL injection (SQLi) attacks allow a malicious individual to perform SQL transactions directly against the backend database through a website front end.
#### Dynamic-link library (DLL)
DLL library injection or DLL hijacking is an advanced software exploitation technique that manipulates a process's memory to trick it into loading additional code and thus performing operations the original author did not intend.
#### Lightweight Directory Access Protocol (LDAP)
Lightweight directory access protocol (LDAP) injection is an input injection against a LDAP directory service.
#### Extensible Markup Language (XML)
XML injection is another variant of SQL injection, where the backend target is an XML application.
### Pointer/object dereference
Pointer dereferencing or object dereference is the programmatic activity of retrieving the value stored in a memory location by triggering the pulling of the memory based on its address or location as stored in a pointer.

### Directory traversal
A directory traversal is an attack that enables an attacker to jump out of the web root directory structure and into any other part of the filesystem hosted by the web server's host OS.
### Buffer overflows
A buffer overflow is a memory exploitation that takes advantage of a software's lack if input length validation. Some buffer overflows can allow for arbitrary code execution.
### Race conditions
A race condition attack is the manipulation of the completion order of tasks to exploit a vulnerability.
#### Time of check/time of use (TOCTOU)
Time-of-check-to-time-of-use attacks often called race condition attacks because the attacker is racing with the legitimate process to replace the object before it is used.

### Error handling
When a process, a procedure, or an input causes an error, the system should revert to a more secure state.
Improper error handling may allow for the leaking of essential information to attackers or enable attackers to force a system into an insecure state.
On error display a general error message and log the error details.

### Improper input handling
Input handling or filtering should include the following: check for length, filter for known malware patterns, and escape metacharacters.
Improper input handling occurs when an application is designed to simply accept whatever data is submitted as input.
### Replay attack
In a replay attack, an attacker captures network traffic and then replays the captured traffic in an attempt to gain unauthorized access to a system.
Wireless replay attacks may focus on initial authentication abuse. They may be used to simulate numerous new clients and cause a DoS.
#### Session replays
A session replay is the recording if a subject's visit to a website, interacting with a mobile application, or using a PC application, which is then replayed back by the administrator, investigator, or programmer to understand what occurred and why based on the subject's activities.
### Integer overflow
An integer overflow is the state that occurs when a mathematical operation attempts to create a numeric value that is too large to be contained or represented by the allocated storage space or memory structure

### Request forgeries
Request forgeries are exploitations that make malicious request of a service in such a way that the request seems legitimate.
#### Server-side Request Forgery (SSRF)
Server-side forgery is when a vulnerable server is coerced into functioning as a proxy.
#### Cross-site Request Forgery (XSRF/CSRF)
Cross-site forgery tricks the user or the user's browser into performing actions they had not intended or would not have authorized.
### Application programming interface (API) attacks
Malicious usages of the software through its API.
### Resource exhaustion

### Memory leak

### Secure Sockets Layer (SSL) stripping
### Driver manipulation
#### Shimming
#### Refactoring

### Pass the hash



## 1. 4 Given a scenario, analyze potential indicators associated with network attacks.
### Wireless
#### Evil twin
Evil twin is an attack in which a hacker operates a false access point that will automatically clone, or twin, the identity of an access point based on a client device's request to connect.
Use similar SSID.

#### Rogue access point
A rogue WAP may be planted by an employee for convenience, or it may be operated externally by an attacker.
#### Bluesnarfing
Bluesnarfing is the unauthorized accessing of data via a Bluetooth connection
#### Bluejacking
Bluejacking is the sending of unsolicited messages to Bluetooth capable devices without the permissions of the owner/user.
#### Disassociation
Disassociation, a type of wireless management frame, can be used in wireless attacks, including discovering hidden SSID's, causing a DoS, hijacking sessions, and on-path.
#### Jamming
Jamming is the transmission of radio signals to prevent reliable communications by decreasing the effective signal-to-noise ratio.

#### Radio frequency identification (RFID)

#### Near-field communication (NFC)
#### Initialization vector (IV)

### On-path attack (previously known as man-in-the-middle attack/man-in-the-browser attack)
### Layer 2 attacks
#### Address Resolution Protocol (ARP) poisoning
#### Media access control (MAC) flooding
#### MAC cloning
### Domain name system (DNS)
#### Domain hijacking
#### DNS poisoning
#### Uniform Resource Locator (URL) redirection
#### Domain reputation
### Distributed denial-of-service (DDoS)
#### Network
#### Application
#### Operational technology (OT)
### Malicious code or script execution
#### PowerShell
#### Python
#### Bash
#### Macros
#### Visual Basic for Applications (VBA)


## 1.5 Explain different threat actors, vectors, and intelligence sources.
### Actors and threats
#### Advanced persistent threat (APT)
#### Insider threats
#### State actors
#### Hacktivists
#### Script kiddies
#### Criminal syndicates
#### Hackers
##### Authorized
##### Unauthorized
##### Semi-authorized

#### Shadow IT
#### Competitors
### Attributes of actors
#### Internal/external
#### Level of sophistication/capability
#### Resources/funding
#### Intent/motivation

### Vectors
#### Direct access
#### Wireless
#### Email
#### Supply chain
#### Social media
#### Removable media
#### Cloud
### Threat intelligence sources
#### Open-source intelligence (OSINT)
#### Closed/proprietary
#### Vulnerability databases
#### Public/private information-sharing centers
#### Dark web
#### Indicators of compromise
#### Automated Indicator Sharing (AIS)
##### Structured Threat Information eXpression (STIX)/Trusted Automated eXchange of Intelligence Information (TAXII)
#### Predictive analysis
#### Threat maps
#### File/code repositories
### Research sources
#### Vendor websites
#### Vulnerability feeds
#### Conferences
#### Academic journals
#### Request for comments (RFC)
#### Local industry groups
#### Social media
#### Threat feeds
#### Adversary tactics, techniques, and procedures (TTP)


## 1.6 Explain the security concerns associated with various types of vulnerabilities.
### Cloud-based vs. on-premises vulnerabilities
### Zero-day
Unknown vulnerability.
Vulnerability has not been detected or published.
Hard to stop these attach since we don't know about it.
### Weak configurations
#### Open permissions
Data accessible to anyone because have bad permissions
Common with cloud storage

#### Unsecure root accounts
Admin or root account
Misconfiguration, intentionally configured an easy password or left default password
Disable direct login to root account to prevent this
Protect root account (policies)

#### Errors
Error messages can provide useful information to an attacker.
Errors to user should be general
Detailed error information should be logged

#### Weak encryption
Use strong encryption protocol (ASE, 3DES, ...)
Length of key
Hash used for integrity check
Stay up to date with cipher suite
TLS: over 300 cipher suites with some better then other
Avoid weak or null encryption (less than 128 bit keys sizes), outdated hashes (MD5)

#### Unsecure protocols
Some protocols are not encrypted
- All traffic sent in cleartext
- Telnet, ftp, smtp, imap
Use encrypted versions
- ssh, sftp, imaps, ...

#### Default settings
Change default user and password

#### Open ports and services
Import to manage access
Often managed by firewall

### Third-party risks
#### Vendor management
##### System integration
##### Lack of vendor support
#### Supply chain
#### Outsourced code development
#### Data storage
### Improper or weak patch management

#### Firmware
#### Operating system (OS)
#### Applications

### Legacy platforms
### Impacts
#### Data loss
#### Data breaches
#### Data exfiltration
#### Identity theft
#### Financial
#### Reputation
#### Availability loss

## 1.7 Summarize the techniques used in security assessments.
### Threat hunting
#### Intelligence fusion
#### Threat feeds
#### Advisories and bulletins
#### Maneuver
### Vulnerability scans
#### False positives
#### False negatives
#### Log reviews
#### Credentialed vs. non-credentialed
#### Intrusive vs. non-intrusive
#### Application
#### Web application
#### Network
#### Common Vulnerabilities and Exposures (CVE)/Common Vulnerability Scoring System (CVSS)
#### Configuration review
### Syslog/Security information and event management (SIEM)
#### Review reports
#### Packet capture
#### Data inputs
#### User behavior analysis
#### Sentiment analysis
#### Security monitoring
#### Log aggregation
#### Log collectors
### Security orchestration, automation, and response (SOAR)

## 1.8 Explain the techniques used in penetration testing.
### Penetration testing
#### Known environment
#### Unknown environment
#### Partially known environment
#### Rules of engagement
#### Lateral movement
#### Privilege escalation
#### Persistence
#### Cleanup
#### Bug bounty
#### Pivoting
### Passive and active reconnaissance
#### Drones
#### War flying
#### War driving
#### Footprinting
#### OSINT
### Exercise types
#### Red-team
#### Blue-team
#### White-team
#### Purple-team


# 2.0 Architecture and Design
## 2.1 Explain the importance of security concepts in an enterprise environment.
### Configuration management
- Diagrams
- Baseline configuration
- Standard naming conventions
- Internet protocol (IP) schema
### Data sovereignty
### Data protection
- Data loss prevention (DLP)
- Masking
- Encryption
- At rest
- In transit/motion
- In processing
- Tokenization
- Rights management

### Geographical considerations
### Response and recovery controls
### Secure Sockets Layer (SSL)/Transport Layer Security (TLS) inspection
### Hashing
### API considerations
### Site resiliency
- Hot site
- Cold site
- Warm site
### Deception and disruption
- Honeypots
- Honeyfiles
- Honeynets
- Fake telemetry
- DNS sinkhole

## 2.2 Summarize virtualization and cloud computing concepts.
### Cloud models
- Infrastructure as a service (IaaS)
- Platform as a service (PaaS)
- Software as a service (SaaS)
- Anything as a service (XaaS)
- Public
- Community
- Private
- Hybrid
### Cloud service providers
### Managed service provider (MSP)/managed security service provider (MSSP)
### On-premises vs. off-premises
### Fog computing
### Edge computing
### Thin client
### Containers
### Microservices/API

### Infrastructure as code
- Software-defined networking (SDN)
- Software-defined visibility (SDV)
### Serverless architecture
### Services integration
### Resource policies
### Transit gateway
### Virtualization
- Virtual machine (VM) sprawl avoidance
- VM escape protection

## 2.3 Summarize secure application development, deployment, and automation concepts.
### Environment
- Development
- Test
- Staging
- Production
- Quality assurance (QA)
### Provisioning and deprovisioning
### Integrity measurement
### Secure coding techniques
- Normalization
- Stored procedures
- Obfuscation/camouflage
- Code reuse/dead code
- Server-side vs. client-side execution and validation
- Memory management
- Use of third-party libraries and software development kits (SDKs)
- Data exposure
### Open Web Application Security Project (OWASP)
### Software diversity
- Compiler
- Binary
### Automation/scripting
- Automated courses of action
- Continuous monitoring
- Continuous validation
- Continuous integration
- Continuous delivery
- Continuous deployment
### Elasticity
### Scalability
### Version control

## 2.4 Summarize authentication and authorization design concepts.
### Authentication methods
- Directory services
- Federation
- Attestation
- Technologies
		 - Time-based one-time password (TOTP)
		 - HMAC-based one-timepassword (HOTP)
		 - Short message service (SMS)
		 - Token key
		 - Static codes
		 - Authentication applications
		 - Push notifications
		 - Phone call
- Smart card authentication
### Biometrics
- Fingerprint
- Retina
- Iris
- Facial
- Voice
- Vein
- Gait analysis
- Efficacy rates
- False acceptance
- False rejection
- Crossover error rate

### Multifactor authentication (MFA) factors and attributes
#### Factors
##### Something you know
Something in your brain
Password: Secret word/phrase, string of characters
PIN: Personal identification number (ATM card)
Pattern: On cell phone
##### Something you have
Device of some type of system
Smart card: integrates with devices, may require a PIN
USB Token: Certificate is on the USB device
Hardware or software tokens: Generates pseudo-random authentication codes
Your Phone: SMS a code to your phone

##### Something you are
Biometric authentication: fingerprint, iris scan, voice print
Difficult to change: can change password but can't change fingerprint
Not fool proof

#### Attributes
##### Somewhere you are
Provide a factor based on your location: transaction only completes if you are in a particular geography
IP Address: Not perfect but can help provide more info (Works with IPv4 but not so much with IPv6)
Mobile device location services: Geolocation to a very specific area. GPS not perfect.
##### Something you can do
A personal way of doing things: Signature

##### Something you exhibit
A unique trait, personal to you
Gait analysis- the way you walk
Typing analysis - the way you hit the enter key to hard

##### Someone you know
A social factor
It's not what you know...
Web of trust
Digital signature
### Authentication, authorization,and accounting (AAA)
Identification: This is who you claim you are (username)
Authentication: prove who you are (password, biometrics, ...)
Authorization: What do you have access too (folders, files, printer)
Accounting: Keeping track (logs)
### Cloud vs. on-premises requirements
- Cloud-based security
Third-party can manage the platform
Centralized platform
Automation options with API integration
May include additional options
- On-premises authentication system
Internal monitoring and management
Need internal expertise
External access must be granted and managed


## 2.5 Given a scenario, implement cybersecurity resilience.
### Redundancy
- Geographic dispersal
- Disk
		 - Redundant array of inexpensive disks (RAID) levels
		 - Multipath
- Network
		 - Load balancers
		 - Network interface card (NIC) teaming
- Power
		 - Uninterruptible power supply (UPS)
		 - Generator
		 - Dual supply
		 - Managed power distribution units (PDUs)
### Replication
- Storage area network
- VM
### On-premises vs. cloud
### Backup types
- Full
- Incremental
- Snapshot
- Differential
- Tape
- Disk
- Copy
- Network-attached storage (NAS)
- Storage area network
- Cloud
- Image
- Online vs. offline
- Offsite storage
		 - Distance considerations
### Non-persistence
- Revert to known state
- Last known-good configuration
- Live boot media
### High availability
- Scalability
### Restoration order
### Diversity
- Technologies
- Vendors
- Crypto
- Controls


## 2.6 Explain the security implications of embedded and specialized systems.
### Embedded systems
- Raspberry Pi
- Field-programmable gate array (FPGA)
- Arduino
### Supervisory control and data acquisition (SCADA)/industrial control system (ICS)
- Facilities
- Industrial
- Manufacturing
- Energy
- Logistics
### Internet of Things (IoT)
- Sensors
- Smart devices
- Wearables
- Facility automation
- Weak defaults
### Specialized
- Medical systems
- Vehicles
- Aircraft
- Smart meters
### Voice over IP (VoIP)
### Heating, ventilation, air conditioning (HVAC)
### Drones
### Multifunction printer (MFP)
### Real-time operating system (RTOS)
### Surveillance systems
### System on chip (SoC)
### Communication considerations
- 5G
- Narrow-band
- Baseband radio
- Subscriber identity module (SIM) cards
- Zigbee
### Constraints
- Power
- Compute
- Network
- Crypto
- Inability to patch
- Authentication
- Range
- Cost
- Implied trust

## 2.7 Explain the importance of physical security controls.
### Bollards/barricades
### Access control vestibules
### Badges
### Alarms
### Signage
### Cameras
- Motion recognition
- Object detection
### Closed-circuit television (CCTV)
### Industrial camouflage
### Personnel
- Guards
- Robot sentries
- Reception
- Two-person integrity/control
### Locks
- Biometrics
- Electronic
- Physical
- Cable locks
### USB data blocker
### Lighting
### Fencing
### Fire suppression
### Sensors
- Motion detection
- Noise detection
- Proximity reader
- Moisture detection
- Cards
- Temperature
### Drones
### Visitor logs
### Faraday cages
### Air gap
### Screened subnet (previously known as demilitarized zone)
### Protected cable distribution
### Secure areas
- Air gap
- Vault
- Safe
- Hot aisle
- Cold aisle
### Secure data destruction
- Burning
- Shredding
- Pulping
- Pulverizing
- Degaussing
- Third-party solutions


## 2.8 Summarize the basics of cryptographic concepts.
### Digital signatures
### Key length
### Key stretching
### Salting
### Hashing
### Key exchange
### Elliptic-curve cryptography
### Perfect forward secrecy
### Quantum
- Communications
- Computing
### Post-quantum
### Ephemeral
### Modes of operation
- Authenticated
- Unauthenticated
- Counter
### Blockchain
- Public ledgers
### Cipher suites
- Stream
- Block
### Symmetric vs. asymmetric
### Lightweight cryptography
### Steganography
- Audio
- Video
- Image
### Homomorphic encryption
### Common use cases
- Low power devices
- Low latency
- High resiliency
- Supporting confidentiality
- Supporting integrity
- Supporting obfuscation
- Supporting authentication
- Supporting non-repudiation
### Limitations
- Speed
- Size
- Weak keys
- Time
- Longevity
- Predictability
- Reuse
- Entropy
- Computational overheads
- Resource vs. security constraints

# 3.0 Implementation

## 3.1 Given a scenario, implement secure protocols.
### Protocols
#### Domain Name System Security Extensions (DNSSEC)
Domain Name System Security Extensions (DNSSEC) is a security improvement to the existing DNS infrastructure. The primary function of DNSSEC is to provide mutual certificate authentication.
#### Secure Shell (SSH)
TCP port 22
Replace Telnet (TCP port 23).

#### Secure/Multipurpose Internet Mail Extensions (S/MIME)
Secure/Multipurpose Internet Mail Extensions is an internet standard for encrypting and digitally signing email. S/MIME uses X.509 v3 standard certificates issued by a trusted CA.
Requires a PKI.

#### Secure Real-time Transport Protocol (SRTP)
Secure RTP
Keep conversations private
Uses AES to encrypt the voice/video flow
Authentication, integrity, and replay protection using HMAC-SHA1 hash  based message authentication code using SHA1

#### Lightweight Directory Access Protocol Over SSL (LDAPS)
Protocol for reading and writing directories over an IP network
LDAPS over SSL

SASL (Simple Authentication and Security Layer)
#### File Transfer Protocol, Secure (FTPS)
FTPS is FTP over SSL(TLS)
#### SSH File Transfer Protocol (SFTP)
Use SSH to provide encryption

#### Simple Network Management Protocol, version 3 (SNMPv3)
Provides confidentiality (encrypted data)
Provides Integrity (no tampering of data)
Provides Authentication (verifies the source)
#### Hypertext transfer protocol over SSL/TLS (HTTPS)
HTTP over TLS / HTTP Secure
#### IPSec
Confidentiality and integrity.
Authentication header (AH) : Integrity
Encapsulating Security Payloads (ESP): Confidentiality
Tunnel/transport

#### Post Office Protocol (POP)/Internet Message Access Protocol (IMAP)
Use a STARTTLS extension to encrypt POP3 with SSL or use IMAP with SSL

#### Network Time Protocol (NTP)
No security
NTPSec
### Use cases
#### Voice and video
SRTP
- Time synchronization
NTPSec
- Email and web
POP3 and IMAP
- File transfer
SFTP (SSH)
FTPS (FTP over SSL)
- Directory services
LDAPS
- Remote access
SSH
- Domain name resolution
DNSSEC
- Routing and switching
SSH, SNMPv3, HTTPS
- Network address allocation
DHCP not security in original implementation
Avoid Rogue DHCP servers using Active Directory to authorize DHCP Server
Some switches can be configured with trusted interfaces: DHCP is only allowed from trusted interface
Cisco calls this DHCP snooping
DHCP client DoS - Starvation attack - spoofed MAC addresses --- run out of place in MAC table: to prevent config limit of mac per interface

- Subscription services
Automated subscriptions: Anti-virus/Anti-Malware signatures updates, IPS updates, Malicious IP address databases/Firewall updates
Must check every single device how this is performed.
Check for encryption and integrity checks: may require additional public key, set up trust relationship
Configure firewall to make sure to only accept updates from trusted sites.

## 3.2 Given a scenario, implement host or application security solutions.
### Endpoint protection
- Antivirus
- Anti-malware
- Endpoint detection and response (EDR)
- DLP
- Next-generation firewall (NGFW)
- Host-based intrusion prevention system (HIPS)
- Host-based intrusion detection system (HIDS)
- Host-based firewall
### Boot integrity
- Boot security/Unified Extensible Firmware Interface (UEFI)
- Measured boot
- Boot attestation
### Database
- Tokenization
- Salting
- Hashing
### Application security
- Input validations
- Secure cookies
- Hypertext Transfer Protocol (HTTP) headers
- Code signing
- Allow list
- Block list/deny list
- Secure coding practices
- Static code analysis
		 - Manual code review
- Dynamic code analysis
- Fuzzing
### Hardening
- Open ports and services
- Registry
- Disk encryption
- OS
- Patch management
	  - Third-party updates
		- Auto-update
### Self-encrypting drive (SED)/full-disk encryption (FDE)
- Opal
### Hardware root of trust
### Trusted Platform Module (TPM)
### Sandboxing


## 3.3 Given a scenario, implement secure network designs.
### Load balancing
- Active/active
- Active/passive
- Scheduling
- Virtual IP
- Persistence
### Network segmentation
- Virtual local area network (VLAN)
- Screened subnet (previously known as demilitarized zone)
- East-west traffic
- Extranet
- Intranet
- Zero Trust
### Virtual private network (VPN)
- Always-on
- Split tunnel vs. full tunnel
- Remote access vs. site-to-site
- IPSec
- SSL/TLS
- HTML5
- Layer 2 tunneling protocol (L2TP)
### DNS
### Network access control (NAC)
- Agent and agentless
### Out-of-band management
### Port security
- Broadcast storm prevention
- Bridge Protocol Data Unit (BPDU) guard
- Loop prevention
- Dynamic Host Configuration Protocol (DHCP) snooping
- Media access control (MAC) filtering
### Network appliances
- Jump servers
- Proxy servers
		- Forward
		- Reverse
- Network-based intrusion detection system (NIDS)/network-based intrusion prevention system (NIPS)
		- Signature-based
		- Heuristic/behavior
		- Anomaly
		- Inline vs. passive
- HSM
- Sensors
- Collectors
- Aggregators
- Firewalls

	  - Web application firewall (WAF)
 	  - NGFW
 		- Stateful
    Stateful firewalls remember the 'state' of the session
    Everything within a valid flow is allowed
		- Stateless
    Does not keep track of traffic flows
    Each packet is individually examined, regardless  of past history
    Traffic sent outside of an active session will traverse a stateless filewall
    Rare today to see a stateless firewall

		- Unified threat management (UTM)
		- Network address translation (NAT) gateway
		- Content/URL filter
		- Open-source vs. proprietary
		- Hardware vs. software
		- Appliance vs. host-based vs. virtual
### Access control list (ACL)
### Route security
### Quality of service (QoS)
### Implications of IPv6
### Port spanning/port mirroring
- Port taps
### Monitoring services
### File integrity monitors


## 3.4 Given a scenario, install and configure wireless security settings.
### Cryptographic protocols
- WiFi Protected Access 2 (WPA2)
- WiFi Protected Access 3 (WPA3)
- Counter-mode/CBC-MAC Protocol (CCMP)
- Simultaneous Authentication of Equals (SAE)
### Authentication protocols
- Extensible Authentication Protocol (EAP)
- Protected Extensible Authentication Protocol (PEAP)
- EAP-FAST
- EAP-TLS
- EAP-TTLS
- IEEE 802.1X
- Remote Authentication Dial-in User Service (RADIUS) Federation
### Methods
- Pre-shared key (PSK) vs. Enterprise vs. Open
- WiFi Protected Setup (WPS)
- Captive portals
### Installation considerations
- Site surveys
- Heat maps
- WiFi analyzers
- Channel overlaps
- Wireless access point (WAP) placement
- Controller and access point security

## 3.5 Given a scenario, implement secure mobile solutions.
### Connection methods and receivers
- Cellular
- WiFi
- Bluetooth
- NFC
- Infrared
- USB
- Point-to-point
- Point-to-multipoint
- Global Positioning System (GPS)
- RFID
• Mobile device management (MDM)
- Application management
- Content management
- Remote wipe
- Geofencing
- Geolocation
- Screen locks
- Push notifications
- Passwords and PINs
- Biometrics
- Context-aware authentication
- Containerization
- Storage segmentation
- Full device encryption
### Mobile devices
- MicroSD hardware security module (HSM)
- MDM/Unified Endpoint Management (UEM)
- Mobile application management (MAM)
- SEAndroid
### Enforcement and monitoring of:
- Third-party application stores
- Rooting/jailbreaking
- Sideloading
- Custom firmware
- Carrier unlocking
- Firmware over-the-air (OTA) updates
- Camera use
- SMS/Multimedia Messaging Service (MMS)/Rich Communication Services (RCS)
- External media
- USB On-The-Go (USB OTG)
- Recording microphone
- GPS tagging
- WiFi direct/ad hoc
- Tethering
- Hotspot
- Payment methods
### Deployment models
- Bring your own device (BYOD)
- Corporate-owned personally enabled (COPE)
- Choose your own device (CYOD)
- Corporate-owned
- Virtual desktop infrastructure (VDI)

## 3.6 Given a scenario, apply cybersecurity solutions to the cloud.
### Cloud security controls
- High availability across zones
- Resource policies
- Secrets management
- Integration and auditing
- Storage
		- Permissions
		- Encryption
		- Replication
		- High availability
- Network
		 - Virtual networks
		 - Public and private subnets
		 - Segmentation
		 - API inspection and integration
- Compute
		 - Security groups
		 - Dynamic resource allocation
		 - Instance awareness
		 - Virtual private cloud (VPC) endpoint
		 - Container security
### Solutions
- CASB
- Application security
- Next-generation secure web gateway (SWG)
- Firewall considerations in a cloud environment
		- Cost
		- Need for segmentation
		- Open Systems Interconnection (OSI) layers
### Cloud native controls vs.third-party solutions


## 3.7 Given a scenario, implement identity and account management controls.
### Identity
- Identity provider (IdP)
- Attributes
- Certificates
- Tokens
- SSH keys
- Smart cards
###  Account types
- User account
- Shared and generic accounts/credentials
- Guest accounts
- Service accounts
### Account policies
- Password complexity
- Password history
- Password reuse
- Network location
- Geofencing
- Geotagging
- Geolocation
- Time-based logins
- Access policies
- Account permissions
- Account audits
- Impossible travel time/risky login
- Lockout
- Disablement

## 3.8 Given a scenario, implement authentication and authorization solutions.
### Authentication management
- Password keys
- Password vaults
- TPM
- HSM
- Knowledge-based authentication
### Authentication/authorization
- EAP
- Challenge-Handshake Authentication Protocol (CHAP)
- Password Authentication Protocol (PAP)
- 802.1X
- RADIUS
- Single sign-on (SSO)
- Security Assertion Markup Language (SAML)
- Terminal Access Controller Access Control System Plus (TACACS+)
- OAuth
- OpenID
- Kerberos
### Access control schemes
- Attribute-based access control (ABAC)
- Role-based access control
- Rule-based access control
- MAC
- Discretionary access control (DAC)
- Conditional access
- Privileged access management
- Filesystem permissions

## 3.9 Given a scenario, implement public key infrastructure.
### Public key infrastructure (PKI)
- Key management
- Certificate authority (CA)
- Intermediate CA
- Registration authority (RA)
- Certificate revocation list (CRL)
- Certificate attributes
- Online Certificate Status Protocol (OCSP)
- Certificate signing request (CSR)
- CN
- Subject alternative name
- Expiration
### Types of certificates
- Wildcard
- Subject alternative name
- Code signing
- Self-signed
- Machine/computer
- Email
- User
- Root
- Domain validation
- Extended validation
### Certificate formats
- Distinguished encoding rules (DER)
- Privacy enhanced mail (PEM)
- Personal information exchange (PFX)
- .cer
- P12
- P7B
• Concepts
- Online vs. offline CA
- Stapling
- Pinning
- Trust model
- Key escrow
- Certificate chaining

## 4.0 Given a scenario, use the appropriate tool to assess organizational security.
### Network reconnaissance and discovery
- tracert/traceroute
- nslookup/dig
- ipconfig/ifconfig
- nmap
- ping/pathping
- hping
- netstat
- netcat
- IP scanners
- arp
- route
- curl
- theHarvester
- sn1per
- scanless
- dnsenum
- Nessus
- Cuckoo
### File manipulation
- head
- tail
- cat
- grep
- chmod
- logger
### Shell and script environments
- SSH
- PowerShell
- Python
- OpenSSL
### Packet capture and replay
- Tcpreplay
- Tcpdump
- Wireshark
### Forensics
- dd
- Memdump
- WinHex
- FTK imager
- Autopsy
### Exploitation frameworks
### Password crackers
### Data sanitization

## 4.2 Summarize the importance of policies, processes, and procedures for incident response.
### Incident response plans
### Incident response process
- Preparation
- Identification
- Containment
- Eradication
- Recovery
- Lessons learned
### Exercises
- Tabletop
- Walkthroughs
- Simulations
### Attack frameworks
- MITRE ATT&CK
- The Diamond Model of Intrusion Analysis
- Cyber Kill Chain
### Stakeholder management
### Communication plan
### Disaster recovery plan
### Business continuity plan
### Continuity of operations planning (COOP)
### Incident response team
### Retention policies

## 4.3 Given an incident, utilize appropriate data sources to support an investigation.
### Vulnerability scan output
### SIEM dashboards
- Sensor
- Sensitivity
- Trends
- Alerts
- Correlation
### Log files
- Network
- System
- Application
- Security
- Web
- DNS
- Authentication
- Dump files
- VoIP and call managers
- Session Initiation Protocol (SIP) traffic
### syslog/rsyslog/syslog-ng
### journalctl
### NXLog
### Bandwidth monitors
### Metadata
- Email
- Mobile
- Web
- File
### Netflow/sFlow
- Netflow
- sFlow
- IPFIX
### Protocol analyzer output

## 4.4 Given an incident, apply mitigation techniques or controls to secure an environment.
### Reconfigure endpoint security solutions
- Application approved list
- Application blocklist/deny list
- Quarantine
### Configuration changes
- Firewall rules
- MDM
- DLP
- Content filter/URL filter
- Update or revoke certificates
### Isolation
### Containment
### Segmentation
### SOAR
- Runbooks
- Playbooks

4.5 Explain the key aspects of digital forensics.
### Documentation/evidence
- Legal hold
- Video
- Admissibility
- Chain of custody
- Timelines of sequence of events
		 - Time stamps
		 - Time offset
- Tags
- Reports
- Event logs
- Interviews
### Acquisition
- Order of volatility
- Disk
- Random-access memory (RAM)
- Swap/pagefile
- OS
- Device
- Firmware
- Snapshot
- Cache
- Network
- Artifacts
### On-premises vs. cloud
- Right-to-audit clauses
- Regulatory/jurisdiction
- Data breach notification laws
### Integrity
- Hashing
- Checksums
- Provenance
### Preservation
### E-discovery
### Data recovery
### Non-repudiation
### Strategic intelligence/counterintelligence

# 5.0 Governance, Risk, and Compliance
## 5.1 Compare and contrast various types of controls.
### Category
- Managerial
- Operational
- Technical
### Control type
- Preventive
- Detective
- Corrective
- Deterrent
- Compensating
- Physical

## 5.2 Explain the importance of applicable regulations, standards, or frameworks that impact organizational security posture.
### Regulations, standards, and legislation
- General Data Protection Regulation (GDPR)
- National, territory, or state laws
- Payment Card Industry Data Security Standard (PCI DSS)
### Key frameworks
- Center for Internet Security (CIS)
- National Institute of Standards and Technology (NIST) Risk Management Framework (RMF)/ Cybersecurity Framework (CSF)
- International Organization for Standardization (ISO) 27001/27002/27701/31000
- SSAE SOC 2 Type I/II
- Cloud security alliance
   	 - Cloud control matrix
		 - Reference architecture
### Benchmarks /secure configuration guides
- Platform/vendor-specific guides
		- Web server
		- OS
		- Application server
		- Network infrastructure devices


## 5.3 Explain the importance of policies to organizational security.
### Personnel
- Acceptable use policy
- Job rotation
- Mandatory vacation
- Separation of duties
- Least privilege
- Clean desk space
- Background checks
- Non-disclosure agreement (NDA)
- Social media analysis
- Onboarding
- Offboarding
- User training
		- Gamification
		- Capture the flag
		- Phishing campaigns
		  - Phishing simulations
		- Computer-based training (CBT)
		- Role-based training
### Diversity of training techniques
### Third-party risk management
- Vendors
- Supply chain
- Business partners
- Service level agreement (SLA)
- Memorandum of understanding (MOU)
- Measurement systems analysis (MSA)
- Business partnership agreement (BPA)
- End of life (EOL)
- End of service life (EOSL)
- NDA

### Data
- Classification
	Data owner
- Governance
- Retention
### Credential policies
- Personnel
- Third-party
- Devices
- Service accounts
- Administrator/root accounts
### Organizational policies
- Change management
- Change control
- Asset management

## 5.4 Summarize risk management processes and concepts.
### Risk types
- External
- Internal
- Legacy systems
- Multiparty
- IP theft
- Software compliance/licensing
### Risk management strategies
- Acceptance
- Avoidance
- Transference
		 - Cybersecurity insurance
- Mitigation
### Risk analysis
- Risk register
- Risk matrix/heat map
- Risk control assessment
- Risk control self-assessment
- Risk awareness
- Inherent risk
- Residual risk
- Control risk
- Risk appetite
- Regulations that affect risk posture
- Risk assessment types
		- Qualitative
		- Quantitative
- Likelihood of occurrence
- Impact
- Asset value
- Single-loss expectancy (SLE)
- Annualized loss expectancy (ALE)
- Annualized rate of occurrence (ARO)
### Disasters
- Environmental
- Person-made
- Internal vs. external
### Business impact analysis
- Recovery time objective (RTO)
- Recovery point objective (RPO)
- Mean time to repair (MTTR)
- Mean time between failures (MTBF)
- Functional recovery plans
- Single point of failure
- Disaster recovery plan (DRP)
- Mission essential functions
- Identification of critical systems
- Site risk assessment


## 5.5 Explain privacy and sensitive data concepts in relation to security.
### Organizational consequences of privacy and data breaches
- Reputation damage
- Identity theft
- Fines
- IP theft
### Notifications of breaches
- Escalation
- Public notifications and disclosures
### Data types
- Classifications
		- Public
		No impact on org.
		Web site.
		- Private
		Contains data that should only be used within org. (Social Security Number, ...)
		- Sensitive
		Might have minimal impact on org
		- Confidential
		High classification data.
		Intellectual Property, source code
		- Critical
		- Proprietary
- Personally identifiable information (PII)
- Health information
- Financial information
- Government data
- Customer data
### Privacy enhancing technologies
- Data minimization
- Data masking
- Tokenization
- Anonymization
- Pseudo-anonymization
### Roles and responsibilities
#### Data owners
A senior (Executive) role with ultimate responsibility for maintaining the confidentiality, integrity and availability of the information asset
The data owner is responsible for labeling the asset and ensuring that it is protected with appropriate controls
Should be owner per department. Data owner should be the person who knows about the data (ex. Accountant, ...)
#### Data steward
A role focused on the quality of the data and associated metadata (Make sure data is correctly label as per the Data Owner request)
#### Data custodian
A role responsible (System Administrator) for handling the management of the system on which the data assets are stored (encryption, backup, ..)
#### Privacy Officer
A role responsible for the oversight of any PII/SPI/PHI assets managed by the company

#### Data controller
TODO
#### Data processor
TODO
#### Data protection officer (DPO)
TODO

### Information life cycle
### Impact assessment
### Terms of agreement
### Privacy notice