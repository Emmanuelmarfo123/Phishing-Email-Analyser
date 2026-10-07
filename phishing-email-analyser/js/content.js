/*
 * content.js — example messages, the awareness challenge, and training lessons.
 *
 * All names, companies and domains in this file are invented for training.
 * IP addresses use ranges reserved for documentation (192.0.2.x, 198.51.100.x, 203.0.113.x).
 */
(function (root) {
  'use strict';
  const P = root.PEA;

  // ── Examples for the analyser ("Try an example") ──────────────────────────
  const EXAMPLES = [
    { id: 'cred', label: 'Fake account suspension', mode: 'email', text:
`From: "Microsoft 365 Security" <no-reply@micros0ft-support.top>
Reply-To: account-team@secure-mailbox-help.xyz
Authentication-Results: mx.contoso.example; spf=fail smtp.mailfrom=micros0ft-support.top; dkim=none; dmarc=fail
Subject: [URGENT] Unusual sign-in activity – mailbox will be suspended

Dear Mailbox User,

We detected unusual sign-in activity on your account. To avoid permanent suspension, you must verify your account within 24 hours.

Sign in to verify: https://login.microsoftonline.com <http://203.0.113.45/office365/verify.php>

If you do not confirm your password today, your mailbox will be permanently deleted.

Microsoft 365 Security Team` },
    { id: 'bec', label: 'CEO gift-card request', mode: 'email', text:
`From: "Daniel Weber (CEO)" <daniel.weber.ceo@gmail.com>
Subject: Quick favour

Hi, are you at your desk? I need you to handle a quick favour for me.
I'm in a meeting and can't take calls. I need 6 Apple gift cards (€200 each) for a client today. Scratch off the back and send me photos of the codes by end of day.

Please keep this confidential for now — it's a surprise.

Daniel
Sent from my iPhone` },
    { id: 'invoice', label: 'Malicious invoice', mode: 'email', text:
`From: Accounts Receivable <billing@nordline-logistics.example>
Subject: Overdue invoice INV-20931 – final notice

Hello,

Please find attached the overdue invoice. Payment is due immediately to avoid late penalties.

Attachments: INV-20931.pdf.exe, Remittance_Details.docm

The document is protected. If you see a yellow bar, click "Enable Content" to view it.
Note: our bank details have changed. Please use the new IBAN in the attached form for all future payments.

Regards,
Accounts Receivable` },
    { id: 'vish', label: 'Vishing call transcript', mode: 'voice', text:
`Caller: Good afternoon, this is Mark calling from your bank's fraud department. We've blocked an unauthorised transaction of 2,400 euros on your account.
Caller: To stop it, I need to verify you. Can you read me the code we just sent to your phone?
Caller: Please stay on the line, don't hang up. Your savings are at risk, so we need to move your money to a safe account to protect it.
Caller: I'll also need you to install AnyDesk so our security team can secure your online banking. This is urgent — the fraudsters are active right now.` },
    { id: 'legit', label: 'Normal work email', mode: 'email', text:
`From: Maria Keller <maria.keller@contoso.example>
Subject: Agenda for Thursday's planning session

Hi team,

Attached is the agenda for Thursday's planning session (agenda-q4.pdf). We'll meet in room 3.12 at 10:00 and finish by 12:00. Lunch will be provided afterwards.

If you can't make it, just let me know and I'll share the notes.

Thanks,
Maria` }
  ];

  // ── Awareness challenge ───────────────────────────────────────────────────
  const CHALLENGE = [
    { id: 'c1', kind: 'Email', from: '"PayPal" <service@paypal-resolution-center.com>', subject: 'Your account access has been limited',
      body: 'Dear Customer,\n\nWe noticed unusual activity and have limited your account. To restore access, confirm your login details within 48 hours:\n\nhttps://paypal-resolution-center.com/restore\n\nFailure to verify will result in permanent closure.',
      phish: true, flags: ['pressure', 'credentials', 'impersonation', 'links', 'headers'],
      explain: '"paypal-resolution-center.com" is not owned by PayPal. Generic greeting, a deadline, a threat of closure and a request to "confirm login details": a classic credential phish.' },
    { id: 'c2', kind: 'Email', from: 'Jonas Becker <jonas.becker@yourcompany.example>', subject: 'Notes from today\'s stand-up',
      body: 'Hi all,\n\nQuick summary from today: the release moves to Wednesday, Priya is covering support on Friday, and the retro is in the usual Teams channel.\n\nShout if I missed anything.\nJonas',
      phish: false, flags: [], explain: 'Internal sender, no links, no attachments, no requests for anything sensitive, and the content matches normal work. Nothing here asks you to act.' },
    { id: 'c3', kind: 'SMS', from: '+49 1521 0000000', subject: 'Text message',
      body: 'DHL: Your parcel could not be delivered due to an unpaid customs fee of €1.99. Pay now to avoid return: https://bit.ly/dhl-fee-pay',
      phish: true, flags: ['money', 'impersonation', 'links', 'pressure'],
      explain: 'Delivery-fee "smishing" is extremely common. A shortened link hides the real site, and the tiny fee is bait to collect your full card details.' },
    { id: 'c4', kind: 'Email', from: '"Daniel Weber" <d.weber.office@gmail.com>', subject: 'Are you available?',
      body: 'Are you at your desk? I need you to process an urgent payment to a new supplier today. Their bank details have changed, I will send the new IBAN. I\'m in a meeting and can\'t talk, keep this between us for now.',
      phish: true, flags: ['money', 'impersonation', 'pressure', 'headers'],
      explain: 'CEO-fraud (BEC): an executive name on a Gmail address, urgency, secrecy, unavailability and a bank-detail change. Always verify by phone using a known number.' },
    { id: 'c5', kind: 'Email', from: 'GitHub <noreply@github.com>', subject: '[GitHub] A new SSH key was added to your account',
      body: 'Hey nana-dev!\n\nA new public key was added to your account.\n\nIf you did this, no further action is needed. If you didn\'t, visit https://github.com/settings/keys to remove it.\n\nThanks,\nThe GitHub Team',
      phish: false, flags: [],
      explain: 'Uses your username, comes from github.com, the link goes to github.com, and it does not demand anything. Still, the safest habit is to open GitHub yourself rather than via the link.' },
    { id: 'c6', kind: 'Email', from: 'IT Service Desk <it-support@yourcompany-helpdesk.net>', subject: 'MFA re-registration required',
      body: 'Due to a security upgrade all staff must re-register MFA today. Our technician will call you; please read the 6-digit code you receive to them to complete verification. Accounts not updated by 17:00 will be disabled.',
      phish: true, flags: ['mfa', 'pressure', 'impersonation', 'headers'],
      explain: 'IT will never ask you to read out an MFA code. Note the look-alike domain "yourcompany-helpdesk.net" and the deadline with a threat.' },
    { id: 'c7', kind: 'Email', from: 'Accounts <billing@supplier-invoices.example>', subject: 'Invoice 88412 overdue',
      body: 'Hello,\n\nPlease see the attached overdue invoice: Invoice_88412.xlsm\n\nIf the content does not display, click "Enable Content" at the top.\n\nRegards',
      phish: true, flags: ['attachments', 'money', 'pressure'],
      explain: 'A macro-enabled spreadsheet (.xlsm) plus "Enable Content" is a malware delivery pattern. Unexpected invoices should be checked with the supplier directly.' },
    { id: 'c8', kind: 'Voice', from: 'Incoming call: "Sparkasse" (spoofed caller ID)', subject: 'Phone call',
      body: '"Hello, this is the fraud team at your bank. We\'ve stopped a suspicious payment. To cancel it I need you to confirm the code we just sent by SMS, and please stay on the line, don\'t hang up."',
      phish: true, flags: ['mfa', 'impersonation', 'pressure'],
      explain: 'Caller ID can be faked. A real bank will never ask you to read out a code. Hang up and call the number on the back of your card.' },
    { id: 'c9', kind: 'Email', from: 'Microsoft <account-security-noreply@accountprotection.microsoft.com>', subject: 'Microsoft account security code',
      body: 'Please use the following security code for your Microsoft account.\n\nSecurity code: 482915\n\nIf you didn\'t request a code, you can safely ignore this email.',
      phish: false, flags: [],
      explain: 'This is a genuine-style code delivery: official microsoft.com sender, no link, no request to share the code. Only a problem if someone then asks you for it.' },
    { id: 'c10', kind: 'Email', from: '"HR Department" <hr@yourcompany.example>', subject: 'Updated salary review – action needed',
      body: 'Dear employee,\n\nYour 2026 salary adjustment letter is ready. Open the secure document to view: <a href="http://hr-docs.yourcompany.example.secure-view.top/login">https://hr.yourcompany.example/letters</a>\n\nYou will need to sign in with your corporate credentials.',
      phish: true, flags: ['credentials', 'links', 'impersonation'],
      explain: 'The link text shows a company address, but the real link goes to "secure-view.top". Salary and HR lures are very effective because people want to know.' },
    { id: 'c11', kind: 'Email', from: 'Lufthansa <online@booking-lufthansa.com>', subject: 'You have been selected for a free upgrade!',
      body: 'Congratulations! You\'ve been selected for a free Business Class upgrade. Claim your reward within 24 hours by confirming your card details for the €0.00 verification charge: https://lufthansa-upgrade.click/claim',
      phish: true, flags: ['money', 'pressure', 'impersonation', 'links'],
      explain: 'Too good to be true, a deadline, card details for a "€0 charge", and a .click domain that the airline does not own.' },
    { id: 'c12', kind: 'Email', from: 'Your Bank <info@yourbank.example>', subject: 'Your monthly statement is available',
      body: 'Hello Nana,\n\nYour statement for September is now available in online banking. For your security, we do not include links in our emails. Please sign in through our app or by typing our address into your browser.\n\nYour Bank',
      phish: false, flags: [],
      explain: 'Personal greeting, no links, no attachments, and it explicitly tells you to use the app. This is what good security communication looks like.' }
  ];

  // ── Training modules (one per skill) ───────────────────────────────────────
  const TRAINING = {
    pressure: {
      summary: 'Pressure is the engine of social engineering. When you feel rushed, frightened or excited, the thinking part of the brain takes a back seat. Attackers manufacture that feeling on purpose.',
      signs: ['Deadlines measured in hours or minutes', 'Threats: account closure, fines, legal action, arrest', 'Excitement: prizes, refunds, upgrades', '"Final notice" for something you have never heard of'],
      do: ['Pause. Urgency is a reason to slow down, not speed up.', 'Ask: "Would this organisation really contact me like this?"', 'Verify through a channel you choose, not one they give you.'],
      quiz: { q: 'An email says your mailbox will be deleted in 2 hours unless you log in. What is the best first step?', options: ['Log in quickly to be safe', 'Reply asking if it is real', 'Open your mail portal yourself (not via the link) or ask IT', 'Forward it to colleagues to warn them'], answer: 2, why: 'Go to the service yourself. Replying talks to the attacker, and forwarding may spread the link.' }
    },
    credentials: {
      summary: 'Most phishing aims to steal a username and password. Fake login pages can be pixel-perfect copies, so the page looking real tells you nothing. The address bar is what matters.',
      signs: ['Asks you to "verify", "confirm" or "re-enter" your password', 'Login link that goes to an unfamiliar or look-alike domain', 'Password "expiring" notices with a link', 'Shared document that needs your work login to view'],
      do: ['Never log in from a link in an unexpected message', 'Use a password manager: it will not autofill on a fake domain', 'Turn on phishing-resistant MFA (passkeys / security keys) where available'],
      quiz: { q: 'Your password manager does not offer to fill your password on a "Microsoft" login page you reached from an email. What does this suggest?', options: ['The password manager is broken', 'The page is probably not on a real Microsoft domain', 'You should type the password in manually', 'Microsoft changed its website'], answer: 1, why: 'Password managers match the exact domain, which makes them a great phishing detector.' }
    },
    mfa: {
      summary: 'MFA (multi-factor authentication) stops most account takeovers, so attackers try to trick you into handing over the code or approving their login prompt ("MFA fatigue").',
      signs: ['Anyone asking you to read out or forward a code', 'Login prompts you did not start, especially repeated ones', '"IT" calling to "re-register" your MFA'],
      do: ['Never share a code. Not with IT, your bank, or the police', 'Deny unexpected prompts and report them: your password is probably compromised', 'Prefer number-matching or passkeys over simple "Approve" buttons'],
      quiz: { q: 'You get five MFA push notifications at 23:00 that you did not trigger. What should you do?', options: ['Approve one to make them stop', 'Deny them, change your password and report it', 'Ignore them and go to sleep', 'Uninstall the authenticator app'], answer: 1, why: 'Unrequested prompts mean someone has your password. Deny, change it and tell your security team.' }
    },
    money: {
      summary: 'Payment fraud, including fake invoices, gift-card scams and Business Email Compromise (BEC), causes larger losses than almost any other cybercrime. It often needs no malware at all, just a convincing story.',
      signs: ['A new or changed bank account for an existing supplier', 'Requests for gift cards or crypto', 'Invoices you were not expecting', 'Payment requests that bypass the normal approval process'],
      do: ['Verify any bank-detail change by calling a number you already have on file', 'Follow the four-eyes principle for payments', 'Treat gift-card requests from "managers" as fraud until proven otherwise'],
      quiz: { q: 'A long-time supplier emails new bank details. The email address looks right. What do you do?', options: ['Update the details; the address is correct', 'Reply to the email to confirm', 'Call the supplier on the number in your records', 'Pay half to the new account to test it'], answer: 2, why: 'Supplier mailboxes get hacked too, so a correct address is not proof. Use a known phone number.' }
    },
    impersonation: {
      summary: 'Attackers borrow trust from brands, colleagues, executives and authorities. Display names cost nothing to fake; the underlying address, and the request itself, are what count.',
      signs: ['Executive writing from a personal account', 'Display name and email address do not match', 'Requests for secrecy, or "I can\'t talk right now"', 'Generic greeting from a company you have an account with'],
      do: ['Check the actual sender address, not just the name', 'Confirm unusual requests with the person via a known channel', 'Remember: real executives understand verification'],
      quiz: { q: 'Which part of an email sender can an attacker change most easily?', options: ['The display name', 'The domain in DMARC-protected mail', 'Your company\'s mail server logs', 'None of them'], answer: 0, why: 'The display name can be set to anything, so always look at the full address.' }
    },
    links: {
      summary: 'A link has two parts: what it shows and where it really goes. Attackers use look-alike domains, shorteners, raw IP addresses and tricks like "paypal.com@evil.com" to hide the destination.',
      signs: ['Domain is slightly misspelled (paypa1, rnicrosoft)', 'Brand name in front of another domain (paypal.com.secure-login.xyz)', 'Shortened links (bit.ly, tinyurl)', 'Numeric IP addresses instead of names'],
      do: ['Hover (desktop) or long-press (mobile) to preview, without clicking', 'Read the domain right-to-left from the first single "/"', 'When in doubt, type the address yourself'],
      quiz: { q: 'Which domain really owns this link?  https://login.paypal.com.account-check.net/signin', options: ['paypal.com', 'login.paypal.com', 'account-check.net', 'signin'], answer: 2, why: 'The registered domain is the last part before the first single "/": account-check.net.' }
    },
    attachments: {
      summary: 'Attachments deliver malware. Watch the real file type: executables, scripts, disk images, HTML files and macro-enabled Office documents are the usual suspects.',
      signs: ['Double extensions like invoice.pdf.exe', 'Macro documents (.docm, .xlsm) or "Enable Content" instructions', 'Password-protected ZIPs with the password in the email', 'HTML/SVG attachments that open a login page'],
      do: ['Turn on "show file extensions" in your operating system', 'Never enable macros in a document from an email', 'Report unexpected attachments instead of opening them'],
      quiz: { q: 'A document opens and says "Click Enable Content to decrypt this file". What is most likely happening?', options: ['A normal Office security feature', 'A macro is trying to run malicious code', 'The file is corrupted', 'Your licence has expired'], answer: 1, why: 'Enabling content lets macros run. Attackers fake "decrypt" or "view" messages to get you to click it.' }
    },
    vishing: {
      summary: 'Voice phishing uses a phone call or voicemail, sometimes with AI-cloned voices. Caller ID can be spoofed. The tactics are the same as email: authority, urgency, and a request for a secret or money.',
      signs: ['"Bank fraud team", "IT helpdesk" or "police" calling unexpectedly', 'Requests for codes, card details or remote-access apps', '"Safe account" stories', 'Pressure to stay on the line'],
      do: ['Hang up and call back on an official number', 'Never install software at a caller\'s request', 'Agree a code word with family / a callback rule at work'],
      quiz: { q: 'A caller from "your bank" knows your name and last transactions, and asks you to move money to a safe account. What is it?', options: ['A genuine fraud prevention step', 'A scam. Banks never ask this', 'Normal if they know your details', 'Fine if the caller ID shows your bank'], answer: 1, why: 'No bank or police force will ever ask you to move money to a "safe account". Details and caller ID can both be faked or stolen.' }
    },
    headers: {
      summary: 'Email headers are the envelope of a message. SPF, DKIM and DMARC show whether the sending domain really authorised it, and Reply-To shows where your answer actually goes.',
      signs: ['SPF/DKIM/DMARC "fail"', 'Reply-To on a different domain than From', 'Display name containing a different email address', 'Company or executive using Gmail/Outlook.com'],
      do: ['Learn to view full headers in your mail client', 'Treat "pass" as "the domain is real", not "the domain is safe"', 'Report spoofing of your own domain to your mail admin'],
      quiz: { q: 'An email passes SPF, DKIM and DMARC for "micros0ft-support.top". What does that prove?', options: ['It is from Microsoft', 'It really came from micros0ft-support.top, which is not Microsoft', 'It is safe to open', 'Nothing at all'], answer: 1, why: 'Authentication proves which domain sent it. Attackers can register their own look-alike domain and pass every check.' }
    }
  };

  Object.assign(P, { EXAMPLES, CHALLENGE, TRAINING });
})(typeof window !== 'undefined' ? window : globalThis);
