# Study Guide For CompTIA Security+

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
Phishing targetted at group of user or even single user.
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



## Given a scenario, analyze potential indicators to determine the type of attack.

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
#### Fileless virus
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
#### Logic bombs
Code embedded in application or script that is triggered by an event (date/time, application launched, ...).
#### Spyware
#### Keyloggers
#### Remote access Trojan (RAT)
Malware that allows attackers to control the PC from a remote location.
Delivered by: drive-by downloads or malicious attachment in emails.
Growing trend to deliver by Portable Executable (PE)
Collect and log key stroke username, password, in-out email, chat sessions, browser history, take snapshot

#### Rootkit
#### Backdoor
Another way to access to a system (created by malware or by developper)
Malware install backdoor to bypass normal authentication methods.

### Password attacks
#### Spraying
#### Dictionary
#### Brute force
##### Offline
##### Online
#### Rainbow table
#### Plaintext/unencrypted
• Physical attacks
- Malicious Universal 
 Serial Bus (USB) cable
- Malicious flash drive
- Card cloning
- Skimming
• Adversarial artificial intelligence (AI)
- Tainted training data for 
 machine learning (ML)
- Security of machine 
 learning algorithms
• Supply-chain attacks
• Cloud-based vs. on-premises attacks
• Cryptographic attacks
- Birthday
- Collision
- Downgrad