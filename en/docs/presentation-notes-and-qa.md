# CA2 group presentation: content trade-offs and anticipated questions

Premise: 35 minutes of pure presentation, Q&A counted separately; grading values **clarity, live demo, insights discovered, Q&A, and whole-team participation**.

---

## 1. Time budget (35 minutes)

| Section | Minutes | Note |
|------|------|------|
| Opening + honeypot/SSH concepts | 4 | keep it brief, do not turn it into a textbook |
| System build (topology + evidence screenshots) | 4 | one topology diagram + key screenshots, do not read commands step by step |
| Live demo (attack -> capture -> analysis) | 10 | **the centerpiece**, there is a dedicated "demo" grading item |
| Log analysis findings | 8 | conclusions on usernames/passwords/commands/IP tracing + charts |
| Hardening and detection (compressed) | 4 | give only the conclusion and that score curve, leave details for Q&A |
| Security recommendations | 3 | 5 items, each one sentence with a data basis |
| Wrap-up + limitations | 2 | honestly stating limitations actually earns marks |

Whole-team participation is graded: make sure everyone leads at least one section.

---

## 2. What can be cut, and how

**Keep as priority** (directly graded):
- Live demo: attacker machine initiates login -> Cowrie captures it -> analysis script produces a report. This is the core of the "demo" grading item; do not skip it.
- Core findings: top usernames/passwords/commands, IP geographic distribution, threat conclusions.
- The 5 security recommendations (must map to your data).

**Compress the delivery** (deep but time-consuming):
- **The detector + six-step hardening (313 -> 118 points)**: this is your most impressive work, but unfolding it takes 20 minutes. How to cut: cover it with **one sentence + one score-curve chart** --
  "We also built a honeypot detector and used it to cut Cowrie's exposure score by 62%; the full five-layer model and step-by-step comparison are in chapter X of the report."
  Leave the depth for Q&A; the instructor will likely follow up, which catches it nicely.
- **Step-by-step VM build commands**: cut to one topology diagram + "see the user guide".
- **OVA->KVM migration details**: **omit entirely** when speaking; it belongs only to the environment-notes document.
- **Tool code / internal implementation**: do not paste code, only show **what it produces** (reports, charts).

**Generic phrasing for omissions**:
- "In the interest of time, the full details of X are in chapter N of the report; here I give only the conclusion."
- "This part could be a talk on its own; today I give the conclusion, happy to go deeper in Q&A."
- The key is to **signpost**: tell the instructor where things are (which chapter / which document), rather than pretending you did not do them.

---

## 3. If I were the instructor: 20 questions I might ask

> For self-testing. The parenthesis after each is the **point being assessed** (the direction of a good answer), not the answer itself.

**Concepts**
1. What is the essential difference between a honeypot and a firewall / IDS? (a honeypot is lure + intelligence, not blocking)
2. The difference between low-, medium- and high-interaction honeypots? Which is Cowrie, and why? (interaction depth vs risk)
3. Why can you "log in with any password" to Cowrie? Is this a flaw or by design? (lure design, else you cannot capture follow-up behaviour)
4. Password auth vs key auth -- why is the latter more secure? (brute-forceability, credentials can be guessed)

**Build**
5. How are your two machines networked? Why must the honeypot be isolated from the real network? (prevent stepping-stone / lateral movement)
6. Cowrie defaults to 2222 not 22 -- what does that imply in a real deployment? How did you handle it on the VPS? (redirect 22 to 2222)
7. After `cowrie start`, how do you confirm it is really working? Where are the logs? (status / tail json)

**Attack simulation**
8. How many logins did you simulate? How did you choose the wordlist? (>= 20 attempts, source of weak passwords)
9. How does the attack your script simulates differ from a real attacker's behaviour? (real ones are more random, more automated, from broader sources)

**Log analysis**
10. What are the most frequent usernames and passwords? What does that indicate? (root/admin + weak passwords, signs of automated scanning)
11. Which commands do attackers run most often after login? What is each trying to do? (recon: whoami/uname/download payload)
12. How did you do IP geolocation tracing? What is the data source? What are the limitations? (ip-api, free/rate-limited/can be bypassed by proxies)
13. How did you determine the threat level of internal IPs? Is that determination reliable? (rule-based; honestly state it is only a heuristic)
14. Does an X% successful-login rate mean the honeypot's protection is strong or weak? Is this metric even meaningful? (a honeypot is meant to be logged into, so reinterpret the metric)

**Threats and recommendations**
15. What can an attacker "learn" from a compromised system? What is the risk to a real organisation? (information disclosure, foothold, lateral movement)
16. Which of your 5 recommendations is the most important, and why? Which of your data does it map to? (be able to tie a recommendation back to data)
17. Why is "disallow direct root login" useful even if the attacker already has the password? (escalation barrier, auditing)

**Depth and limitations**
18. Can a honeypot be seen through? How would an attacker tell this is a honeypot? (leads into your detector: protocol/filesystem/command-behaviour layers)
19. You cut Cowrie's exposure score from 313 to 118 -- why can it not reach 0? Which layers cannot be changed? (the protocol and auth layers are architectural)
20. What extra risks come with running a honeypot on a VPS? How do you stop it becoming an attack stepping stone? (tighten outbound, process hardening, provider abuse)

---

## 4. On-the-day tips

- **Record a screen capture** of the demo in advance as backup, in case the network/environment breaks live.
- Prepare one chart each for the score curve, the top statistics and the IP distribution -- more effective than reading numbers.
- When asked something you do not know, honestly say "we did not go deep here, but by ... reasoning it should be ..." -- better than making it up.
- Raise limitations proactively (e.g. IPs can be masked by proxies, LAN simulation is not real traffic) -- it shows deeper understanding.
