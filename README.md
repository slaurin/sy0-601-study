-10 6# Study Guide For CompTIA Security+

## 1.0 Threats, Attacks, and Vulnerabilities

### 1.1 Compare and contrast different types of social engineering techniques.

#### Phishing
Malicious SPAM.
Email containing link or attachment for user to click to retrive personal information.
#### Smishing
SMS phishing
#### Vishing
Voice phishing (some automated)
#### Spam
Unwanted email
#### Spam over instant messaging (SPIM)
Unwanted email over messaging
#### Spear phishing
Phishing targetted at group of user or even single user
#### Dumpster diving
Going into the trash/recycle to find information
#### Shoulder surfing
Looking over shoulder to get some info

#### Pharming

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
Identify site where target or group of target are likely to visit and infect this site (more vulnerable). Example, if organization emloyee are big fans of golf, infect web site related to golf that they visit regularly.
#### Typosquatting
Domain name close to actual name ex www.gooogle.com
Reason to pay for erroenous domain:
- Hosting malicious site
- Earning ad revenu
- Reselling domain
#### Pretexting
Add context to conversation before asking real question
#### Influence campaigns
  ##### Hybrid warfare
  ##### Social media
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
Malware that takes control of a user's system or user's data. Attacker's attempt to extort payment from victim.
#### Trojans
Trojan typically looks like something beneficial but is actually malicious, will include a backdoor for example.
In PC trojan can be: - pirated software
                     - useful utility
                     - a game
Many trojan are delivered by drive-by downloads (web servers that was compromised and visiting the site will attempt to download the trojan)
Fake antivirus
#### Worms
Self-replicating malware that travels throught the network without any assistance from host application or user interaction.
Consumes network bandwidth.

#### Potentially unwanted programs (PUPs)
Software including unwanted software. Sometimes legit, other time malware.

#### Fileless virus
Malicious software that runs in memory.
- Memory code injection: malware inject code into legitimate application
- Script-based technique
- Windows registry manipulation

Fileless virus can be embedded within vCard

#### Command and control
Give instruction to bots in botnet
Now used for more then botnet
USe IRC to give bots command but easy to find.
Some attackers use P2P to host command and control.
#### Bots
Bots are software robots
Botnets: multiple computer that act as software bots and work together as a network
Bots in botnets are often called zombies and do the work of the person controlling the botnet
Bot herders: criminal controlling the botnet
Bots check in with the command and control systems to receive their commands to execute

#### Cryptomalware
Ransomware where the data is encrypted. Attacker's ask for a payment in bitcoin and if victim pay they might give the encryption key.
#### Logic bombs
Code embedded in application or script that is triggered by an event (date/time, application launched, ...).

#### Spyware
Monitor's user computer and often includes a keylogger.

#### Keyloggers
#### Remote access Trojan (RAT)
Malware that allows attackers to control the PC from a remote location.
Delivered by: drive-by downloads or malicious attachment in emails.
Growing trend to deliver by Portable Executable (PE)
Collect and log key stroke username, password, in-out email, chat sessions, browser history, take snapshot

#### Rootkit
Use hooking technique to hide.
Have system-level/root access.
Inspectin RAM can allow to discover these hidden hooked processes.
#### Backdoor
Another way to access to a system (created by malware or by developper)
Malware install backdoor to bypass normal authentication methods.

### Password attacks
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
- Malicious Universal Serial Bus (USB) cable
- Malicious flash drive
- Card cloning
- Skimming
### Adversarial artificial intelligence (AI)
#### Tainted training data for machine learning (ML)
#### Security of machine learning algorithms

### Supply-chain attacks
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
### Cross-site scripting
### Injections
#### Structured query language (SQL)
#### Dynamic-link library (DLL)
#### Lightweight Directory Access Protocol (LDAP)
#### Extensible Markup Language (XML)

### Pointer/object dereference

### Directory traversal
### Buffer overflows

### Race conditions
#### Time of check/time of use

### Error handling
### Improper input handling
### Replay attack

#### Session replays
### Integer overflow

### Request forgeries
#### Server-side
#### Cross-site

### Application programming interface (API) attacks

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
#### Rogue access point
#### Bluesnarfing
#### Bluejacking
#### Disassociation
#### Jamming
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
### Weak configurations
#### Open permissions
#### Unsecure root accounts
#### Errors
#### Weak encryption
#### Unsecure protocols
#### Default settings
#### Open ports and services
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