# ITSD010 Computing and Cybersecurity Fundamentals
## CA2 Group Assignment: full requirements summary — Oct 2026 Term

> Compiled from the following four sources:
> 1. *CA2 Oct 2026.pdf* — Instruction for the CA2 Group Assignment
> 2. *Cowrie Setup Guide.pdf* — VM and honeypot setup guide
> 3. Canvas page *CA002 Group Assignment Submission & Feedback* — group assignment submission requirements
> 4. Canvas page *CA002 Presentation Submission & Feedback* — presentation submission requirements

---

## Part 1: Assessment Overview

- **Total**: 100 marks, constituting **40%** of the overall assessment.
- **Group size**: groups of **3 to 5 members**.
- **Core task**: deploy a **Cowrie SSH Honeypot** in a controlled virtual environment, simulate attack activity, collect security logs, and analyse attacker behaviour.
- **No programming is required.**

### Four deliverables (ALL must be completed)

| # | Deliverable | Marks | % of overall |
|---|---|---|---|
| 1 | Written Project Report | 25 | 10% |
| 2 | Honeypot Deployment and Evidence | 40 (35 + 5 bonus) | 16% |
| 3 | User Guide with Screenshots | 10 | 4% |
| 4 | Oral Presentation | 25 | 10% |
| | **Total** | **100** | |

### The six things students must do
1. Build two Ubuntu Virtual Machines.
2. Configure the Cowrie honeypot on VM A.
3. Launch SSH login attempts from VM B.
4. Collect and analyse security logs.
5. Write a cybersecurity report.
6. Present the group's findings.

### The assignment focuses on
- Cybersecurity awareness
- Security monitoring
- Basic Linux administration
- Log analysis
- Security recommendations

---

## Part 2: The Case

A small company has recently suffered multiple suspicious login attempts against its servers. Management wants to understand:
- how attackers try to gain unauthorised access;
- which usernames and passwords are most often targeted;
- what activities attackers perform after successfully entering the system.

As a team of junior cybersecurity analysts, your group is tasked with deploying a honeypot system and investigating attacker behaviour. The company needs a simple monitoring solution that can:
- record login attempts;
- capture usernames and passwords used;
- log commands executed by attackers;
- generate cybersecurity findings;
- recommend security improvements.

---

## Part 3: Project Requirement

### Network Environment
- **VM A (Server)**: Ubuntu Server, with Cowrie Honeypot and an SSH service installed.
- **VM B (Client)**: Ubuntu Desktop/Server, used to connect to the honeypot, simulate login attempts and execute commands.

### Task 1: Cybersecurity Research
Research the following concepts:
- **Honeypots**: definition, purpose, benefits, limitations.
- **SSH**: what is SSH? Common uses, security risks.

**Deliverable**: a short discussion, approximately **500 words**.

### Task 2: Deploy the Honeypot
- Configure VM A and install Ubuntu.
- Provide screenshots showing: VM configuration, Cowrie installation, Cowrie running successfully.
- **Required evidence**: `cowrie start`, `cowrie status`.
- **Do not deploy the VM using cloud services, and do not make the honeypot publicly accessible.**

### Task 3: Simulate SSH Login Attempts
Use VM B to complete at least **20 login attempts**:
- Example usernames: `admin`, `root`, `administrator`, `student`, `guest`
- Example passwords: `password`, `123456`, `admin123`, `student123`, `welcome`
- Example command: `ssh admin@<ip-address> -p 2222`
- After login, run simple commands: `ls`, `pwd`, `whoami`, `uname -a`
- The aim is to generate log data for analysis.
- You **must only test against your own group's honeypot**.

### Task 4: Log Analysis
Analyse the information Cowrie captures and answer:
- **Login Analysis**: total login attempts; most-used usernames; most-used passwords; number of successful logins.
- **Command Analysis**: most common commands; the purpose of those commands.
- **Threat Findings**: what can an attacker learn from a compromised system? What risks does it pose to the organisation?

**Presentation requirement**: at least **one table**, **one bar chart**, **one pie chart**.

### Task 5: Security Recommendations
Provide at least **5 security recommendations**, each with a brief explanation. Examples:
- Strong password policies
- Multi-factor authentication (MFA)
- Disable direct root login
- Regular patching

### Additional Feature (up to 5 bonus marks)
Implement any one of:
- Geo-location analysis of attacker IP addresses
- Visualization dashboard
- Daily attack summary report
- Comparison with real-world cyberattack statistics

### Suggested Group Roles

| Role | Responsibility |
|---|---|
| Member 1 | Project Leader & Documentation |
| Member 2 | VM Installation & Network Setup |
| Member 3 | Cowrie Installation |
| Member 4 | Attack Simulation |
| Member 5 | Log Analysis & Presentation |

---

## Part 4: Report & User Guide Requirements

### The Project Report must contain
1. Cover Page
2. Introduction
3. Honeypot Research
4. System Setup
5. Log Analysis
6. Findings and Discussion
7. Security Recommendations
8. Conclusion

Include screenshots and explanations.

### The User Guide must show step by step
1. Starting Cowrie
2. Connecting to the Honeypot
3. Generating Login Attempts
4. Viewing Logs
5. Stopping Cowrie

### Honeypot Deployment Evidence (needed in both the report and the user guide)
- Screenshots of VM setup
- Screenshots of Cowrie installation
- Screenshots showing successful login attempts
- Screenshots of log files

### Presentation
- **All members must be present.**
- The presentation should include: project overview, demonstration, findings, recommendations.

### Formatting for the CA2 Report and User Guides
- **Cover page**: must include the school name (and logo), programme and module name, term and year, and submission date, all **centred**.
- On the cover page, write your **FULL name and student number** as per the registration list. Students should keep a copy of the assignment they submit.
- **Report length**: minimum **1,500 words**.
- **Referencing**: provide references for research material, cybersecurity resources and websites consulted; **APA referencing format** recommended.
- **Font and spacing**: Times New Roman, size 12, 1.5 line spacing.

### Penalty Marks for Late Submission
- One day late (within 24 hours): **20%** deducted from the total.
- More than one day late (over 24 hours): **NOT graded / graded zero**.

### Plagiarism and Collusion
- You may not reuse old assignments, submit projects from previous terms, or heavily copy sources (especially from the internet).
- The submitted report must demonstrate the student's own work; no marks are given without working or reasonable explanation.
- Plagiarism and collusion are serious offences; all cases are referred to administration. If plagiarism or collusion is suspected, marks are withheld until the investigation is complete.

### Important Dates
- **CA2 Group Assignment deadline: 10 November 2026, 11:59 a.m.**
- Submit the project via **Canvas**; the report is graded only once submission is complete.
- **Lecturer contact**: for any questions, contact the lecturer via your SIM email.

---

## Part 5: Marking Rubric

> Note: some descriptive text in the original PDF rubric was missing/incomplete on extraction; the following is organised from the readable content. Bands from high to low are Excellent -> Very Good -> Good -> Acceptable -> Weak.

### 1. Project Report (25 marks)

| Criteria | Excellent | Weak |
|---|---|---|
| Introduction & Understanding of Honeypots | detailed and accurate explanation of honeypots, SSH, cybersecurity risks and objectives | minimal or inaccurate explanation |
| Documentation | clearly documents all setup steps, comprehensive descriptions with screenshots | very little setup documentation |
| Log Analysis & Interpretation | detailed analysis and interpretation of login attempts, passwords, commands and attack patterns | little or no meaningful analysis |
| Security Recommendations | practical, well-argued recommendations supported by the analysis findings | few or irrelevant recommendations |
| Clarity & Presentation of Report | excellently organised, professional, clear and easy to follow | poorly organised, difficult to follow |

### 2. Honeypot Deployment & Evidence (40 marks)

| Criteria | Excellent | Weak |
|---|---|---|
| Virtual Machine Setup | both VMs correctly configured, network connectivity established, setup fully documented | incomplete or non-functional |
| Cowrie Installation | installed successfully with all required evidence provided | Cowrie not functioning or insufficient evidence |
| Attack Simulation | all required login attempts completed and meaningful activity logs generated | insufficient attack simulation activities |
| Evidence Collection | comprehensive screenshots covering all major activities and system states | little or no evidence |
| Technical Accuracy | demonstrates an excellent understanding of the honeypot's deployment and operation | poor technical understanding |

### 3. User Guides (10 marks)

| Criteria | Excellent | Weak |
|---|---|---|
| Step-by-Step Instructions | clear, logical instructions throughout | instructions are unclear |
| Screenshot Samples | screenshots cover all major steps | few or no screenshots |
| Accuracy of Procedures | all steps accurate and easy to follow | many inaccuracies |
| Sample Inputs and Outputs | detailed command and log examples provided and explained | few or no examples |
| Professional Presentation | well formatted, suitable for non-technical users | poorly formatted |

### 4. Oral Presentation (25 marks)

| Criteria | Excellent | Weak |
|---|---|---|
| Clarity of Presentation | clear, confident, well structured | lacks clarity in some areas |
| Demonstration of System | the group confidently and accurately demonstrates the complete honeypot system | no meaningful demonstration |
| Content & Findings | insightful findings, well explained and supported | unclear or unsupported findings |
| Questions & Answers | answers all questions accurately and confidently | unable to answer questions |
| Team Participation | all members participate equally and effectively | minimal group participation |

---

## Part 6: Cowrie Setup Guide (full text)

### A. VM Setup Guide
1. Download and install **Oracle VirtualBox** from:
   - https://www.virtualbox.org/wiki/Downloads
   - https://mega.nz/file/sNsGiBJC#6PHAChdguWYNgtfGzYz3WAdfGAerg8yJc-DYKua6jio
2. Download the ZIP from cloud storage and extract it; you should get **two .ova files** (extraction password: **ditccf**).
3. In VirtualBox, go to **File → Import Appliance**.
4. Click "**Choose a virtual appliance file to import**", select the .ova file and start the import.
5. After importing both VMs, right-click each VM and choose **Settings**, switch to **Expert Mode** and select **Network**, confirming:
   - **Attached to**: Bridged Adapter
   - **Name**: your computer's Wi-Fi adapter
   - **Promiscuous Mode**: Allow VMs

### B. Cowrie Server User Guide
1. Before starting the VM, make sure you are connected to a **home or private network** that **does not require domain authentication**.
2. Start the Cowrie VM.
3. Log in with username **ubuntucowrie** and password **123456**.
4. Run `ip addr` to get the Cowrie VM's IP; note the IP assigned to the **enp0s3** interface (needed later).
5. Switch from root to the cowrie user: `sudo su - cowrie`
6. Enter the Cowrie directory: `cd ~/cowrie-honeypot`
7. Activate the Cowrie virtual environment: `source cowrie-env/bin/activate`
8. Commands to manage the Cowrie honeypot service:
   - `cowrie start` — start the honeypot
   - `cowrie status` — check the honeypot status
   - `cowrie stop` — stop the honeypot
9. Monitor the Cowrie logs live:
   - `tail -f var/log/cowrie/cowrie.log`
   - `tail -f var/log/cowrie/cowrie.json`
10. Keep the Cowrie server running, then switch to the client VM.

### C. Client VM User Guide
1. Confirm the Cowrie honeypot service is running on the server.
2. Start the Client VM (login user: **ubuntuclient**).
3. Verify network connectivity to the Cowrie server: `ping -c 4 x.x.x.x`
   (Replace x.x.x.x with the Cowrie server's IP, and make sure the connection is established.)
4. From the Client VM, manually launch SSH login attempts.

**Example SSH Login Commands:**
```
ssh root@x.x.x.x -p 2222
ssh admin@x.x.x.x -p 2222
ssh ubuntu@x.x.x.x -p 2222
ssh test@x.x.x.x -p 2222
```
(Replace x.x.x.x with the Cowrie server's IP. Any password works — the honeypot captures the credentials and allows the login attempt.)

**Example Commands After Login:**
```
whoami
pwd
uname -a
id
ls -la
cat /etc/passwd
ps aux
netstat -tulnp
```

**Testing File Download Monitoring:**
```
wget http://example.com/test.sh
curl http://example.com/file.txt
```

5. After completing the login attempts and running commands, return to the Cowrie server to view the log records.
6. To transfer log files from the VM to your local computer, use an **SCP connection**.

---

## Part 7: Canvas Submission Requirements

### 7.1 Group Assignment Submission (CA002 Group Assignment Submission & Feedback)
- **Due**: **10 November, 11:59 a.m.**
- **Method**: file upload
- **Accepted file types**: doc, docx, java, pdf, zip, png, jpg, jpeg
- **Submission window**: 1 October 00:00 — 11 November 11:59 a.m.

#### Submission rules
- Use the provided template to guide the report writing: **Guide Template for Assignment** (downloadable on the Canvas page).
- Follow the instructions carefully; **failure to follow them incurs penalty marks**.
- The CA must be written in **MS Word** and saved as **FamilynameFirstname.docx** (surname + given name), e.g. `TanMeiMeiSally.docx`, `PremaSubroyan.docx` (omit D/O, S/O).
- The document extension may be ".doc" (97-2003 format) or ".docx".
- The file must be compatible with **Plagiarism Detection**: the uploaded file must **not** be password protected, encrypted, hidden, a system file, or read only. Acceptable file types:
  - Microsoft Word (DOC and DOCX)
  - Microsoft Excel (XLS and XLSX)
  - Microsoft PowerPoint (PPT and PPTS)
  - Plain text (TXT)
  - Rich Text Format (RTF)
  - Portable Document Format (PDF)
- The submitted document must have **more than 20 words**, be **smaller than 40MB** (about two million characters), be **no more than 400 pages**, and must not have a space between every letter (e.g. "l i k e t h i s").
- The Canvas submission system allows **multiple submissions** before the deadline; **each new submission overwrites the previous file**, so every submission must include all files to ensure completeness.

#### Declaration
By submitting this assignment online we/I declare that we/I have read and understood the following statements:
- (a) This project assignment is our/my original work; apart from parts with due acknowledgment, no part is copied from any other source or written by someone else.
- (b) We/I understand the meaning of the following concepts:
  - **What plagiarism is**: using all or part of another's work as one's own, verbatim or closely paraphrased, without acknowledging the original author. Examples in an assignment include using another author's phrases, facts and illustrations, statistics and assembled materials without acknowledgment.
  - **What collusion is**: using another's work or ideas with their consent without formally acknowledging it in your own work. Although students may freely discuss ideas and group projects with anyone, when writing the report each student / each group must write their own report in their own words. Identical phrases, paragraphs, sections of text or illustrations across different groups' reports (without acknowledgment) constitute collusion.
- (c) We/I understand that plagiarism and/or collusion are serious offences. Students found to have plagiarised, colluded, or allowed their work to be copied will be subject to SIM's disciplinary procedures.

#### Ensuring successful submission
- The page has an "**IMPORTANT: Click Here**" link (guidance on confirming successful submission).

#### Getting Help
- Before submitting, carefully read the Student Portal, Course Overview, Assessment Overview, CA Schedule, Examination Schedule and the information in Canvas.
- For issues: first check the Canvas Help section; if you still need help with Canvas submission, click the link on the page to follow the steps to contact the Service Desk; for non-Canvas issues, email **students@sim.edu.sg** from your student mymail account (mail from other accounts is not accepted).
- Please read all instructions thoroughly before asking further questions.

#### Penalty Marks for Late Submission
- Within 24 hours: **20%** deducted from the total.
- More than 24 hours: submission is **graded zero**.

#### Peer Evaluation (group assignments only)
- To promote team spirit, use the Peer Evaluation Form (downloadable on the Canvas page) **ONLY IF YOU HAVE EVIDENCE THAT ANY GROUP MEMBER HAS NOT CONTRIBUTED THEIR PART**.
- Send the form to **he10@sim.edu.sg** by **2 p.m. on 12 November 2026**.

#### Academic Integrity
- Students must follow all academic integrity guidelines and the specific requirements of the assignment brief; the page includes an *Academic Integrity Guide* infographic summarising the main academic misconduct to avoid.

#### Declaration of Academic Integrity and Use of AI Tools
By submitting this assignment you confirm:
- I have followed all academic integrity guidelines and assignment requirements;
- this work is original and complies with all academic integrity and AI use rules;
- I take full responsibility for this submission and have provided AI prompt records where required.

**Acknowledgement:**
- I understand that a false, incomplete or misleading declaration may lead to disciplinary action under SIM's academic misconduct procedures;
- I understand that failing to provide the required declaration and AI prompt records may result in this assignment **not being marked**.

### 7.2 Presentation Submission (CA002 Presentation Submission & Feedback)
- **Due**: **21 November, 11:59 a.m.**
- **Method**: file upload
- **Accepted file types**: pdf, doc, docx, ppt, pptx, xls, xlsx, txt, rtf, mp4
- **Submission window**: 1 October 00:00 — 22 November 11:59 a.m.
- The **Canvas submission window opens one week before the deadline**; multiple submissions are allowed before the deadline.

The remaining requirements match the group assignment submission page, including:
- use the **Guide Template for Assignment**, follow the instructions carefully or lose marks;
- file naming **FamilynameFirstname.docx** (surname + given name, omit D/O, S/O), extension .doc or .docx;
- plagiarism-detection compatibility (acceptable types are DOC/DOCX, XLS/XLSX, PPT/PPTX, TXT, RTF, PDF, **video MP4**);
- the document must have more than 20 words, be under 40MB, no more than 400 pages, and have no spaces between letters;
- the same **DECLARATION** of originality, the definitions of Plagiarism and Collusion, and the consequences of misconduct;
- the "IMPORTANT: Click Here" guidance on confirming successful submission;
- getting help (Canvas Help, Service Desk, students@sim.edu.sg via the student mymail account);
- late-submission penalty: within 24 hours **20%**, over 24 hours **zero**;
- the *Academic Integrity Guide* infographic requirement;
- the **Declaration of Academic Integrity and Use of AI Tools** and acknowledgement clauses (failing to provide the declaration and AI prompt records may result in not being marked).

---

## Appendix: key dates at a glance

| Item | Date/time |
|---|---|
| Submission opens | 1 October 2026, 00:00 |
| **Group assignment (report etc.) deadline** | **10 November 2026, 11:59 a.m.** |
| Group assignment submission closes | 11 November 2026, 11:59 a.m. |
| Peer Evaluation Form deadline (send to he10@sim.edu.sg) | 12 November 2026, 2:00 p.m. |
| **Presentation deadline** | **21 November 2026, 11:59 a.m.** |
| Presentation submission closes | 22 November 2026, 11:59 a.m. |
