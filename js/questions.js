const QUESTIONS = {
  module1: [
    {
      question: "What does CIA stand for in cybersecurity?",
      options: [
        "Confidentiality, Integrity, Availability",
        "Central Intelligence Agency",
        "Cybersecurity Infrastructure Act",
        "Control, Identify, Assess"
      ],
      correct: 0,
      explanation: "The CIA Triad is the foundation of cybersecurity. Confidentiality keeps data private, Integrity ensures data isn't tampered with, and Availability keeps systems up and running."
    },
    {
      question: "A hospital's patient records are accessed by an unauthorized employee. Which CIA pillar is violated?",
      options: ["Availability", "Integrity", "Confidentiality", "Authentication"],
      correct: 2,
      explanation: "Confidentiality means only authorized people can access data. An unauthorized person viewing patient records is a confidentiality violation."
    },
    {
      question: "An attacker modifies a company's financial records without anyone knowing. Which CIA pillar is violated?",
      options: ["Confidentiality", "Integrity", "Availability", "Accountability"],
      correct: 1,
      explanation: "Integrity ensures that data is accurate and hasn't been tampered with. Unauthorized modification of records is an integrity violation."
    },
    {
      question: "A DDoS attack floods a web server, making it crash and unavailable to users. Which CIA pillar is violated?",
      options: ["Confidentiality", "Integrity", "Availability", "All three"],
      correct: 2,
      explanation: "Availability means systems and services stay accessible to authorized users. A DDoS attack that takes down a server is an availability attack."
    },
    {
      question: "What is a VULNERABILITY in cybersecurity?",
      options: [
        "Anything that can cause harm to a system",
        "A weakness that can be exploited by a threat",
        "The actual attack carried out against a system",
        "A safeguard put in place to reduce risk"
      ],
      correct: 1,
      explanation: "A vulnerability is a weakness or flaw in a system, software, or process that can be exploited. Example: unpatched software, weak passwords, open ports."
    },
    {
      question: "What is a THREAT in cybersecurity?",
      options: [
        "A weakness in a system",
        "The chance of harm occurring",
        "Anything that has the potential to cause harm",
        "The actual damage caused by an attack"
      ],
      correct: 2,
      explanation: "A threat is anything that has the potential to cause harm — this includes hackers, natural disasters, disgruntled employees, or even software bugs."
    },
    {
      question: "What is RISK in cybersecurity?",
      options: [
        "The actual attack against a system",
        "The potential for loss when a threat exploits a vulnerability",
        "A weakness in software or hardware",
        "A type of malware"
      ],
      correct: 1,
      explanation: "Risk = Threat × Vulnerability. It's the potential for loss or damage when a threat successfully exploits a vulnerability. Risk can be reduced but rarely eliminated."
    },
    {
      question: "What is an EXPLOIT?",
      options: [
        "A type of firewall rule",
        "A weakness in a system",
        "The actual code or technique used to take advantage of a vulnerability",
        "A backup recovery plan"
      ],
      correct: 2,
      explanation: "An exploit is the actual tool, technique, or code used to take advantage of a vulnerability. A vulnerability exists — an exploit is what turns that vulnerability into an active attack."
    },
    {
      question: "Which of the following is an example of an ASSET in cybersecurity?",
      options: [
        "A firewall rule",
        "A phishing email",
        "Customer data stored in a database",
        "A software vulnerability"
      ],
      correct: 2,
      explanation: "An asset is anything of value worth protecting — this includes data, hardware, software, people, and reputation. Customer data is a classic example of a critical asset."
    },
    {
      question: "What is a SECURITY CONTROL?",
      options: [
        "An attack method used by hackers",
        "A safeguard or countermeasure to reduce risk",
        "A type of malware",
        "A vulnerability in a system"
      ],
      correct: 1,
      explanation: "A security control is any safeguard, policy, or countermeasure put in place to reduce risk. Examples include firewalls, encryption, access controls, and security awareness training."
    },
    {
      question: "Which CIA pillar does ENCRYPTION primarily protect?",
      options: ["Availability", "Integrity", "Confidentiality", "Authentication"],
      correct: 2,
      explanation: "Encryption primarily protects Confidentiality by making data unreadable to unauthorized parties. Even if intercepted, encrypted data cannot be read without the decryption key."
    },
    {
      question: "What are the three core goals of cybersecurity?",
      options: [
        "Prevent, Monitor, Recover",
        "Prevent, Detect, Respond",
        "Attack, Defend, Recover",
        "Encrypt, Authenticate, Authorize"
      ],
      correct: 1,
      explanation: "The three core goals of cybersecurity are: Prevent attacks from happening, Detect attacks when they do occur, and Respond effectively to minimize damage."
    }
  ],

  module2: [
    {
      question: "What does DNS stand for?",
      options: [
        "Data Network Security",
        "Domain Name System",
        "Digital Network Service",
        "Dynamic Node Selector"
      ],
      correct: 1,
      explanation: "DNS stands for Domain Name System. It acts like the internet's phone book, translating human-readable domain names (like google.com) into IP addresses (like 142.250.80.46)."
    },
    {
      question: "What port number does HTTPS use?",
      options: ["80", "21", "443", "22"],
      correct: 2,
      explanation: "HTTPS uses port 443. HTTP uses port 80. The difference is that HTTPS encrypts traffic using TLS, making it secure for transmitting sensitive data like passwords and payment info."
    },
    {
      question: "What port number does SSH use?",
      options: ["21", "22", "23", "25"],
      correct: 1,
      explanation: "SSH (Secure Shell) uses port 22. It provides encrypted remote access to systems. This is the secure alternative to Telnet (port 23) which sends data in plain text."
    },
    {
      question: "What is the key difference between HTTP and HTTPS?",
      options: [
        "HTTPS is faster than HTTP",
        "HTTPS uses port 80 while HTTP uses port 443",
        "HTTPS encrypts traffic using TLS, HTTP sends data in plain text",
        "HTTP is newer than HTTPS"
      ],
      correct: 2,
      explanation: "HTTPS uses TLS (Transport Layer Security) to encrypt data in transit. HTTP sends everything in plain text — anyone on the network can intercept and read HTTP traffic using a packet sniffer."
    },
    {
      question: "Which OSI layer handles IP addresses and routing between networks?",
      options: ["Layer 2 — Data Link", "Layer 3 — Network", "Layer 4 — Transport", "Layer 7 — Application"],
      correct: 1,
      explanation: "Layer 3 (Network) handles logical addressing (IP addresses) and routing — determining the best path for data to travel between different networks."
    },
    {
      question: "What is a PRIVATE IP address?",
      options: [
        "An IP assigned by your ISP for internet access",
        "An IP used only inside a local network (LAN) not reachable from the internet",
        "An IP address encrypted for security",
        "An IP assigned to a government server"
      ],
      correct: 1,
      explanation: "Private IP addresses (like 192.168.x.x, 10.x.x.x) are used inside local networks and are not routable on the public internet. Your home router assigns private IPs to your devices."
    },
    {
      question: "What protocol AUTOMATICALLY assigns IP addresses to devices on a network?",
      options: ["DNS", "FTP", "DHCP", "SMTP"],
      correct: 2,
      explanation: "DHCP (Dynamic Host Configuration Protocol) automatically assigns IP addresses, subnet masks, gateways, and DNS servers to devices when they connect to a network."
    },
    {
      question: "What does a ROUTER do?",
      options: [
        "Connects devices within the same local network",
        "Assigns IP addresses automatically",
        "Directs and forwards traffic between different networks",
        "Translates domain names to IP addresses"
      ],
      correct: 2,
      explanation: "A router directs network traffic between different networks (e.g., your home LAN and the internet). A switch connects devices within the same network. Many home devices combine both."
    },
    {
      question: "What is DNS POISONING (also called DNS Cache Poisoning)?",
      options: [
        "A DDoS attack against DNS servers",
        "Corrupting DNS records to redirect users to malicious websites",
        "Encrypting DNS traffic to prevent snooping",
        "Deleting DNS records to cause outages"
      ],
      correct: 1,
      explanation: "DNS poisoning corrupts DNS cache with false records, redirecting users to attacker-controlled sites. Users type a legitimate URL but get sent to a fake site — often used for phishing."
    },
    {
      question: "What port does FTP (File Transfer Protocol) use?",
      options: ["22", "25", "21", "143"],
      correct: 2,
      explanation: "FTP uses port 21. It is an insecure protocol — data including usernames and passwords are sent in plain text. SFTP (port 22) or FTPS should be used instead for secure file transfer."
    },
    {
      question: "Which OSI layer handles ENCRYPTION and data formatting?",
      options: [
        "Layer 3 — Network",
        "Layer 4 — Transport",
        "Layer 5 — Session",
        "Layer 6 — Presentation"
      ],
      correct: 3,
      explanation: "Layer 6 (Presentation) handles data formatting, encryption, and compression. It translates data between the application format and the network format, and handles TLS/SSL encryption."
    },
    {
      question: "What does LAN stand for?",
      options: ["Large Area Network", "Local Area Network", "Logical Access Node", "Line Access Network"],
      correct: 1,
      explanation: "LAN stands for Local Area Network — a network confined to a small geographic area like a home, office, or building. WAN (Wide Area Network) covers larger distances like the internet."
    },
    {
      question: "What is the PRIMARY purpose of a FIREWALL?",
      options: [
        "Assign IP addresses to devices",
        "Translate domain names to IP addresses",
        "Filter and control incoming and outgoing network traffic based on rules",
        "Encrypt data in transit"
      ],
      correct: 2,
      explanation: "A firewall monitors and controls network traffic based on predefined security rules. It can block malicious traffic, restrict access to certain ports, and prevent unauthorized connections."
    },
    {
      question: "Which port does RDP (Remote Desktop Protocol) use?",
      options: ["22", "3389", "443", "8080"],
      correct: 1,
      explanation: "RDP uses port 3389. It allows users to connect to and control a Windows computer remotely. RDP is often targeted by attackers — it should be restricted and protected with strong authentication."
    },
    {
      question: "What is the memory trick for the 7 OSI layers from top to bottom?",
      options: [
        "All People Seem To Need Data Processing",
        "Please Do Not Throw Sausage Pizza Away",
        "Attackers Prefer Simple Threats Not Defense Plans",
        "A Proxy Server Translates Network Data Packets"
      ],
      correct: 0,
      explanation: "Top to bottom (Layer 7 to 1): All (Application) People (Presentation) Seem (Session) To (Transport) Need (Network) Data (Data Link) Processing (Physical). Bottom to top: Please Do Not Throw Sausage Pizza Away."
    }
  ],

  module3: [
    {
      question: "Which type of malware ENCRYPTS your files and demands payment to restore access?",
      options: ["Spyware", "Adware", "Ransomware", "Rootkit"],
      correct: 2,
      explanation: "Ransomware encrypts a victim's files and demands a ransom payment (usually cryptocurrency) for the decryption key. Notable examples include WannaCry and LockBit."
    },
    {
      question: "Which type of malware SPREADS across networks automatically WITHOUT requiring any user action?",
      options: ["Virus", "Trojan", "Worm", "Adware"],
      correct: 2,
      explanation: "Worms self-replicate and spread across networks without user interaction. Unlike viruses, they don't need to attach to a file. WannaCry is a famous worm that spread globally in 2017."
    },
    {
      question: "What is SPEAR PHISHING?",
      options: [
        "Mass phishing emails sent to millions of people",
        "Phishing attacks conducted via phone calls",
        "Highly targeted phishing aimed at a specific individual or organization",
        "Phishing conducted through SMS text messages"
      ],
      correct: 2,
      explanation: "Spear phishing is targeted phishing against a specific person or organization. Attackers research their target and craft convincing, personalized emails — much more dangerous than generic phishing."
    },
    {
      question: "What is TAILGATING in the context of cybersecurity?",
      options: [
        "Following someone's browser history",
        "Physically following an authorized person into a secure area without credentials",
        "Monitoring network traffic from behind a firewall",
        "A type of SQL injection attack"
      ],
      correct: 1,
      explanation: "Tailgating (also called piggybacking) is a physical security attack where an attacker follows an authorized person through a secure door without using their own credentials."
    },
    {
      question: "Which password attack tries EVERY POSSIBLE combination of characters?",
      options: [
        "Dictionary attack",
        "Credential stuffing",
        "Password spraying",
        "Brute force attack"
      ],
      correct: 3,
      explanation: "Brute force attacks try every possible combination of characters until the correct password is found. They are time-consuming but guaranteed to work eventually if given enough time."
    },
    {
      question: "What is CREDENTIAL STUFFING?",
      options: [
        "Trying every possible password combination",
        "Using previously leaked username/password pairs from other breaches to log into accounts",
        "Adding extra characters to common passwords",
        "Sending fake login pages to users"
      ],
      correct: 1,
      explanation: "Credential stuffing uses username/password combinations leaked from previous data breaches, betting that users reuse passwords across multiple sites. This is why unique passwords for every account matter."
    },
    {
      question: "What is a ZERO-DAY attack?",
      options: [
        "An attack that takes exactly zero seconds to execute",
        "An attack that begins at midnight",
        "An attack exploiting a vulnerability that the software vendor doesn't know about yet",
        "An attack targeting systems that have been running for zero days"
      ],
      correct: 2,
      explanation: "A zero-day attack exploits a vulnerability that is unknown to the vendor — meaning there are zero days of protection. There's no patch available because the vulnerability hasn't been discovered and fixed yet."
    },
    {
      question: "What is SQL INJECTION?",
      options: [
        "Injecting malicious scripts into web pages viewed by other users",
        "Inserting malicious SQL code into input fields to manipulate a database",
        "A type of network flood attack",
        "Installing malware via USB drives"
      ],
      correct: 1,
      explanation: "SQL injection inserts malicious SQL code into input fields (like login forms) to manipulate the backend database. Attackers can bypass authentication, extract data, or even delete entire databases."
    },
    {
      question: "What is a MAN-IN-THE-MIDDLE (MitM) attack?",
      options: [
        "An insider threat from a mid-level employee",
        "An attacker secretly intercepting and possibly altering communication between two parties",
        "A physical attack requiring the attacker to be in the same building",
        "A social engineering attack via phone"
      ],
      correct: 1,
      explanation: "In a MitM attack, the attacker secretly positions themselves between two communicating parties, intercepting (and potentially modifying) the data. Both victims believe they're talking directly to each other."
    },
    {
      question: "What is SOCIAL ENGINEERING?",
      options: [
        "Hacking social media platforms",
        "Building social networks for security professionals",
        "Psychologically manipulating people into revealing confidential information or taking unsafe actions",
        "Engineering software for social applications"
      ],
      correct: 2,
      explanation: "Social engineering exploits human psychology rather than technical vulnerabilities. Attackers manipulate trust, fear, urgency, or authority to trick people into giving up information or access."
    },
    {
      question: "What is a ROOTKIT?",
      options: [
        "Malware that floods a server with traffic",
        "A tool for managing system root accounts",
        "Malware that hides deep in the OS, providing persistent stealthy access",
        "A type of ransomware"
      ],
      correct: 2,
      explanation: "A rootkit hides deep within the operating system, often at the kernel level, to conceal malicious activity. They are extremely difficult to detect and remove, often requiring a full system reinstall."
    },
    {
      question: "What is VISHING?",
      options: [
        "Phishing via email",
        "Phishing via SMS text messages",
        "Phishing conducted over voice calls (phone)",
        "Visual phishing using fake website logos"
      ],
      correct: 2,
      explanation: "Vishing (voice phishing) uses phone calls to trick victims. Attackers impersonate bank representatives, IRS agents, or tech support to extract sensitive information like PINs, passwords, or credit card numbers."
    },
    {
      question: "What is SMISHING?",
      options: [
        "Phishing via social media",
        "Phishing via SMS text messages",
        "Phishing via email",
        "Phishing via voice calls"
      ],
      correct: 1,
      explanation: "Smishing (SMS phishing) uses text messages to trick victims. Common examples include fake package delivery alerts, bank fraud warnings, or prize notifications with malicious links."
    },
    {
      question: "What is a BOTNET?",
      options: [
        "A network security monitoring tool",
        "A collection of security bots used by defenders",
        "A network of compromised devices controlled by an attacker to carry out coordinated attacks",
        "An automated software testing framework"
      ],
      correct: 2,
      explanation: "A botnet is a network of infected devices (bots) remotely controlled by an attacker (botmaster) without the owners' knowledge. Botnets are used for DDoS attacks, spam campaigns, and cryptocurrency mining."
    },
    {
      question: "What is PRETEXTING?",
      options: [
        "Sending text messages before a phishing attack",
        "Creating a fabricated scenario (pretext) to manipulate someone into giving up information",
        "Testing systems before a security audit",
        "A form of SQL injection using fake text fields"
      ],
      correct: 1,
      explanation: "Pretexting involves creating a fake but believable scenario to manipulate a victim. Example: 'Hi, I'm from IT — we're doing a security audit and need you to confirm your password.'"
    }
  ],

  module4: [
    {
      question: "What does AAA stand for in cybersecurity?",
      options: [
        "Authentication, Availability, Accountability",
        "Authentication, Authorization, Accounting",
        "Access, Audit, Accountability",
        "Authenticate, Analyze, Act"
      ],
      correct: 1,
      explanation: "AAA stands for Authentication (proving who you are), Authorization (what you're allowed to do), and Accounting (logging what you did). This framework is fundamental to access control systems."
    },
    {
      question: "What is AUTHENTICATION?",
      options: [
        "Determining what resources a user can access",
        "Logging user activity for audit purposes",
        "The process of proving and verifying a user's identity",
        "Encrypting user credentials"
      ],
      correct: 2,
      explanation: "Authentication is the process of verifying identity — proving you are who you claim to be. Common methods include passwords, biometrics, and security tokens."
    },
    {
      question: "What is AUTHORIZATION?",
      options: [
        "Proving who you are to a system",
        "Logging user activity",
        "Determining what an authenticated user is permitted to access or do",
        "Encrypting data in transit"
      ],
      correct: 2,
      explanation: "Authorization happens AFTER authentication. It determines what resources and actions an authenticated user is permitted. You can be authenticated (logged in) but not authorized to access certain resources."
    },
    {
      question: "What is MFA (Multi-Factor Authentication)?",
      options: [
        "Using multiple passwords for the same account",
        "Using two or more different authentication factors to verify identity",
        "Having multiple administrators for a single account",
        "Logging in from multiple devices simultaneously"
      ],
      correct: 1,
      explanation: "MFA requires two or more authentication factors from different categories (something you know, have, or are). Even if an attacker has your password, they still can't access the account without the second factor."
    },
    {
      question: "A fingerprint scan used to unlock a phone is an example of which authentication factor?",
      options: [
        "Something you know",
        "Something you have",
        "Something you are",
        "Somewhere you are"
      ],
      correct: 2,
      explanation: "Biometrics (fingerprint, face recognition, retina scan, voice) are 'something you are' factors. These are based on physical or behavioral characteristics unique to an individual."
    },
    {
      question: "A password is an example of which authentication factor?",
      options: [
        "Something you have",
        "Something you are",
        "Something you know",
        "Somewhere you are"
      ],
      correct: 2,
      explanation: "Passwords, PINs, passphrases, and security questions are all 'something you know' factors — they are knowledge-based. This is the most common but also the weakest factor alone."
    },
    {
      question: "A hardware security token (like a YubiKey) is an example of which authentication factor?",
      options: [
        "Something you know",
        "Something you have",
        "Something you are",
        "Somewhere you are"
      ],
      correct: 1,
      explanation: "Physical devices like smart cards, hardware tokens, and authenticator phones are 'something you have' factors — possession-based. An attacker would need to physically steal the device."
    },
    {
      question: "What is SYMMETRIC ENCRYPTION?",
      options: [
        "Using a public and private key pair for encryption",
        "Encryption that can only encrypt but not decrypt",
        "Using the same key for both encryption and decryption",
        "Encryption based on the user's location"
      ],
      correct: 2,
      explanation: "Symmetric encryption uses one key for both encrypting and decrypting data. It's fast and efficient but requires securely sharing the key with the other party. Examples: AES, DES, 3DES."
    },
    {
      question: "Which hashing algorithm is BEST for storing user passwords?",
      options: ["MD5", "SHA-1", "SHA-256", "bcrypt"],
      correct: 3,
      explanation: "bcrypt is designed specifically for password hashing. It includes a salt (preventing rainbow table attacks) and is intentionally slow, making brute force attacks impractical. MD5 and SHA-1 are cryptographically broken."
    },
    {
      question: "What is the principle of LEAST PRIVILEGE?",
      options: [
        "Give all users administrator access for efficiency",
        "Grant users only the minimum access rights they need to perform their job",
        "Restrict all users from accessing any resources",
        "Only senior employees should have any access"
      ],
      correct: 1,
      explanation: "Least privilege limits user access to only what's necessary for their job. This minimizes the damage from compromised accounts, insider threats, and accidental misuse."
    },
    {
      question: "What is SEPARATION OF DUTIES?",
      options: [
        "Keeping security and IT teams in separate buildings",
        "Dividing critical tasks among multiple people so no single person can commit fraud or error alone",
        "Using different passwords for different systems",
        "Separating development and production environments"
      ],
      correct: 1,
      explanation: "Separation of duties splits critical or sensitive tasks between multiple people. For example: one person creates a payment, a different person approves it. This prevents single points of fraud or error."
    },
    {
      question: "What is RBAC (Role-Based Access Control)?",
      options: [
        "Access based on a user's physical location",
        "Access based on the user's job role within the organization",
        "Access based on the time of day",
        "Access that is completely unrestricted"
      ],
      correct: 1,
      explanation: "RBAC grants permissions based on a user's role (e.g., 'HR Manager', 'Developer', 'Accountant') rather than individual assignment. This simplifies access management in large organizations."
    },
    {
      question: "What does DEFENSE IN DEPTH mean?",
      options: [
        "Having one very strong security control",
        "Burying security devices underground",
        "Using multiple layers of security controls so that if one fails, others still protect the system",
        "Hiring a large security team"
      ],
      correct: 2,
      explanation: "Defense in depth applies multiple security controls at different layers (physical, network, application, data). If one layer is breached, others provide continued protection. Never rely on a single security control."
    }
  ]
};

const FINAL_EXAM_QUESTIONS = [
  // Module 1
  { question: "What does the 'I' in CIA Triad stand for?", options: ["Intelligence", "Integrity", "Integration", "Identity"], correct: 1, explanation: "Integrity ensures data is accurate and hasn't been modified by unauthorized parties.", module: "Module 1" },
  { question: "Ransomware primarily attacks which CIA pillar?", options: ["Confidentiality", "Integrity", "Availability", "Authentication"], correct: 2, explanation: "Ransomware encrypts files making them inaccessible, attacking Availability.", module: "Module 1" },
  { question: "A firewall is an example of a security ___?", options: ["Threat", "Vulnerability", "Exploit", "Control"], correct: 3, explanation: "A security control is any safeguard that reduces risk. A firewall filters traffic to protect systems.", module: "Module 1" },
  { question: "Which term describes the CHANCE that a threat will exploit a vulnerability?", options: ["Exploit", "Asset", "Risk", "Control"], correct: 2, explanation: "Risk is the likelihood that a threat will successfully exploit a vulnerability and cause harm.", module: "Module 1" },
  { question: "An unpatched operating system is an example of a:", options: ["Threat", "Vulnerability", "Exploit", "Risk"], correct: 1, explanation: "An unpatched OS is a weakness (vulnerability) that can be exploited by attackers.", module: "Module 1" },
  { question: "Which CIA pillar does a backup system primarily support?", options: ["Confidentiality", "Integrity", "Availability", "Authorization"], correct: 2, explanation: "Backups ensure data availability by allowing recovery when systems fail or data is lost.", module: "Module 1" },
  // Module 2
  { question: "What port does SMTP use for sending email?", options: ["25", "110", "143", "443"], correct: 0, explanation: "SMTP (Simple Mail Transfer Protocol) uses port 25 for sending email between servers.", module: "Module 2" },
  { question: "Which OSI layer is responsible for end-to-end communication and error checking?", options: ["Layer 2", "Layer 3", "Layer 4", "Layer 5"], correct: 2, explanation: "Layer 4 (Transport) handles end-to-end communication, reliability, and error checking. TCP and UDP operate here.", module: "Module 2" },
  { question: "What does DHCP stand for?", options: ["Dynamic Host Configuration Protocol", "Domain Host Control Protocol", "Digital Host Connection Point", "Data Handling Control Process"], correct: 0, explanation: "DHCP automatically assigns IP addresses and network configuration to devices on a network.", module: "Module 2" },
  { question: "What is packet sniffing?", options: ["Flooding a network with packets", "Capturing and reading network traffic data", "Blocking packets with a firewall", "Encrypting packets for secure transmission"], correct: 1, explanation: "Packet sniffing captures network traffic to read its contents. On unencrypted networks, this can reveal passwords and sensitive data.", module: "Module 2" },
  { question: "Which protocol provides encrypted remote command-line access?", options: ["Telnet", "FTP", "SSH", "HTTP"], correct: 2, explanation: "SSH (Secure Shell) provides encrypted remote access. Telnet does the same but without encryption — it's insecure.", module: "Module 2" },
  { question: "What is the purpose of a switch in a network?", options: ["Connect different networks together", "Assign IP addresses to devices", "Connect devices within the same local network", "Filter internet traffic"], correct: 2, explanation: "A switch connects devices within the same LAN, forwarding data based on MAC addresses. A router connects different networks.", module: "Module 2" },
  // Module 3
  { question: "WHALING is a phishing attack targeting:", options: ["Random email users", "IT department staff", "Senior executives and high-value individuals", "Government employees only"], correct: 2, explanation: "Whaling targets high-value individuals like CEOs, CFOs, and executives. The term reflects 'going after a big fish.'", module: "Module 3" },
  { question: "What attack tries one common password against MANY different accounts?", options: ["Brute force", "Dictionary attack", "Password spraying", "Credential stuffing"], correct: 2, explanation: "Password spraying tries a single common password (like 'Password123!') across many accounts to avoid lockouts. It's effective against weak password policies.", module: "Module 3" },
  { question: "A Trojan differs from a virus because it:", options: ["Spreads automatically across networks", "Disguises itself as legitimate software", "Only attacks databases", "Only infects mobile devices"], correct: 1, explanation: "Trojans disguise themselves as legitimate, useful software. Unlike viruses, they don't replicate — they rely on users running them voluntarily.", module: "Module 3" },
  { question: "What is a RAINBOW TABLE attack?", options: ["A colorful brute force attack", "Using precomputed hash values to crack passwords", "A DDoS attack using multiple colors of traffic", "Injecting code into web applications"], correct: 1, explanation: "Rainbow tables are precomputed tables of hash values. Attackers compare stolen password hashes against the table to find matches. Salting passwords defeats rainbow table attacks.", module: "Module 3" },
  { question: "BAITING as a social engineering technique involves:", options: ["Sending urgent email warnings", "Leaving infected physical media (like USB drives) for victims to find and use", "Making threatening phone calls", "Creating fake websites"], correct: 1, explanation: "Baiting exploits curiosity. Attackers leave infected USB drives in parking lots or public areas, banking on someone plugging it in.", module: "Module 3" },
  { question: "XSS (Cross-Site Scripting) attacks inject malicious code into:", options: ["Database queries", "Websites viewed by other users", "Network packets", "Operating system files"], correct: 1, explanation: "XSS injects malicious scripts into websites. When other users visit the compromised page, their browsers execute the script — potentially stealing session cookies or credentials.", module: "Module 3" },
  { question: "What type of malware silently monitors user activity and sends data to attackers?", options: ["Ransomware", "Adware", "Spyware", "Worm"], correct: 2, explanation: "Spyware silently monitors victims — logging keystrokes, capturing screenshots, tracking browsing habits — and sends the data to attackers.", module: "Module 3" },
  // Module 4
  { question: "ACCOUNTING in the AAA framework refers to:", options: ["Financial security audits", "Logging and tracking user activity for audit purposes", "Billing users for resource usage", "Counting the number of users"], correct: 1, explanation: "Accounting logs who accessed what, when, and what they did. These audit trails are crucial for investigating security incidents and proving compliance.", module: "Module 4" },
  { question: "What is ASYMMETRIC encryption?", options: ["Using the same key for encryption and decryption", "Using a key pair — public key encrypts, private key decrypts", "Encrypting only half the data", "Encryption without any key"], correct: 1, explanation: "Asymmetric encryption uses a key pair. The public key (shared with anyone) encrypts data; only the private key (kept secret) can decrypt it. RSA and ECC are examples.", module: "Module 4" },
  { question: "What is HASHING?", options: ["Encrypting data with a secret key", "A one-way function that converts data into a fixed-length value that cannot be reversed", "Compressing data for storage", "Splitting data into equal parts"], correct: 1, explanation: "Hashing is a one-way function — you can hash data but cannot 'unhash' it. Passwords are stored as hashes so that even if the database is breached, plaintext passwords aren't exposed.", module: "Module 4" },
  { question: "The principle of NEED TO KNOW means:", options: ["Users should know all security policies", "Access is granted based on job function, not just security clearance", "All employees need to know the admin password", "Information is shared openly within a team"], correct: 1, explanation: "Need to know means access to specific information is granted only if it's required for the user's job, even if they have the appropriate security clearance level.", module: "Module 4" },
  { question: "ZERO TRUST security model assumes:", options: ["All internal users are trusted by default", "Trust nobody and verify everything, regardless of network location", "Only external users need to be verified", "Systems inside the firewall are always safe"], correct: 1, explanation: "Zero Trust eliminates the idea of a trusted internal network. Every user, device, and connection must be verified, even inside the corporate network.", module: "Module 4" },
  { question: "MAC (Mandatory Access Control) is commonly used in:", options: ["Most commercial businesses", "Home networks", "Military and government systems requiring strict data classification", "Public websites"], correct: 2, explanation: "MAC enforces strict access based on data classification labels (e.g., Unclassified, Secret, Top Secret) set by the system — not the data owner. Used in government and military environments.", module: "Module 4" },
  { question: "What is DAC (Discretionary Access Control)?", options: ["System-enforced access based on classification labels", "Role-based access based on job function", "Owner-controlled access where the data owner decides who can access it", "Attribute-based access control"], correct: 2, explanation: "In DAC, the data/resource owner has discretion over who gets access. Windows file permissions use DAC — the file owner can grant or revoke access to other users.", module: "Module 4" },
  // Mixed
  { question: "Which attack involves flooding a server with so much traffic it becomes unavailable?", options: ["SQL Injection", "DDoS", "MitM", "Brute Force"], correct: 1, explanation: "DDoS (Distributed Denial of Service) overwhelms a server with traffic from multiple sources, making it unavailable to legitimate users — attacking Availability.", module: "Mixed" },
  { question: "Which of the following uses PORT 443?", options: ["FTP", "SSH", "HTTPS", "RDP"], correct: 2, explanation: "HTTPS uses port 443 for encrypted web traffic. HTTP uses port 80 (unencrypted), SSH uses port 22, FTP uses port 21, RDP uses port 3389.", module: "Mixed" },
  { question: "A SALT in password security is used to:", options: ["Make passwords longer", "Add a unique random value to each password before hashing to defeat rainbow table attacks", "Encrypt passwords symmetrically", "Store passwords in plain text"], correct: 1, explanation: "A salt is a random value added to each password before hashing. Even if two users have the same password, their hashes will be different — defeating rainbow table and precomputed hash attacks.", module: "Mixed" },
  { question: "What three CIA goals does a ransomware attack primarily violate?", options: ["Only Availability", "Confidentiality and Availability", "All three: Confidentiality, Integrity, and Availability", "Only Integrity"], correct: 1, explanation: "Ransomware primarily attacks Confidentiality (data may be exfiltrated) and Availability (files are encrypted and inaccessible). Some ransomware also threatens Integrity by threatening data modification.", module: "Mixed" },
  { question: "Which principle ensures no single employee can both approve AND execute a financial transaction?", options: ["Least Privilege", "Defense in Depth", "Separation of Duties", "Need to Know"], correct: 2, explanation: "Separation of Duties splits critical tasks between multiple people to prevent fraud and error. In finance, the person who initiates a payment should not be the same person who approves it.", module: "Mixed" },
  { question: "The OSI Model has how many layers?", options: ["4", "5", "6", "7"], correct: 3, explanation: "The OSI (Open Systems Interconnection) model has 7 layers: Physical, Data Link, Network, Transport, Session, Presentation, and Application.", module: "Mixed" },
  { question: "What makes SFTP more secure than FTP?", options: ["SFTP uses a different port number", "SFTP encrypts the data transfer", "SFTP is faster", "SFTP doesn't require authentication"], correct: 1, explanation: "SFTP (SSH File Transfer Protocol) encrypts file transfers using SSH. FTP transmits data, including credentials, in plain text — anyone sniffing the network can capture them.", module: "Mixed" },
  { question: "Which authentication factor is a fingerprint?", options: ["Something you know", "Something you have", "Something you are", "Somewhere you are"], correct: 2, explanation: "Biometrics like fingerprints, facial recognition, and retina scans are 'something you are' — inherence factors based on unique physical characteristics.", module: "Mixed" },
  { question: "What type of attack uses previously stolen credentials from one breach to attempt logins on other websites?", options: ["Brute force", "Credential stuffing", "Password spraying", "Pretexting"], correct: 1, explanation: "Credential stuffing reuses username/password pairs leaked from one breach against other sites, exploiting password reuse. This is why unique passwords for every account are critical.", module: "Mixed" },
  { question: "Which layer of the OSI model do IP addresses operate at?", options: ["Layer 2", "Layer 3", "Layer 4", "Layer 7"], correct: 1, explanation: "IP addresses and routing occur at Layer 3 (Network). MAC addresses operate at Layer 2 (Data Link). Ports (TCP/UDP) operate at Layer 4 (Transport).", module: "Mixed" },
  { question: "AES is an example of which type of encryption?", options: ["Asymmetric", "Hashing", "Symmetric", "Public key"], correct: 2, explanation: "AES (Advanced Encryption Standard) is a symmetric encryption algorithm — it uses the same key for both encryption and decryption. It is currently the most widely used symmetric cipher.", module: "Mixed" },
  { question: "Social engineering attacks primarily exploit:", options: ["Software vulnerabilities", "Network weaknesses", "Human psychology and behavior", "Hardware flaws"], correct: 2, explanation: "Social engineering bypasses technical controls by manipulating human psychology — exploiting trust, fear, urgency, and authority. Humans are often called the weakest link in security.", module: "Mixed" }
];
