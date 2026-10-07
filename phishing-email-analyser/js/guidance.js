/*
 * guidance.js — turns findings into human advice.
 *
 * Plain-English summary:
 *   - whatIf(report)     : "What happens if I click / reply / open it?"
 *   - attackPath(report) : the likely step-by-step attack, mapped to MITRE ATT&CK
 *                          (a public catalogue of attacker techniques used by Blue Teams)
 *   - actions(report)    : recommended actions and incident-response steps
 */
(function (root) {
  'use strict';
  const P = root.PEA;

  function flags(report) {
    const id = new Set(report.findings.map(f => f.id));
    const sk = new Set(report.findings.map(f => f.skill));
    const has = (...xs) => xs.some(x => id.has(x));
    return {
      voice: report.mode === 'voice',
      link: report.urls.some(u => u.issues.length) || has('click-lure'),
      anyLink: report.urls.length > 0,
      creds: has('password-request') || (sk.has('links') && sk.has('impersonation')),
      mfa: has('mfa-request'),
      file: report.attachments.some(a => a.issues.length) || has('macros'),
      macro: has('macros', 'att-macro'),
      money: has('payment', 'bank-change', 'invoice', 'prize', 'card-details', 'safe-account'),
      bank: has('bank-change'),
      remote: has('remote-access'),
      callback: has('callback'),
      impersonation: sk.has('impersonation') || has('caller-authority'),
      card: has('card-details'),
      headers: sk.has('headers')
    };
  }

  // ── What happens if… ──────────────────────────────────────────────────────
  function whatIf(report) {
    const f = flags(report);
    const out = [];
    if (f.link || f.anyLink) out.push({
      action: 'Click the link', severity: f.link ? 'high' : 'low',
      steps: [
        'Your browser opens a page controlled by the attacker, often a perfect copy of a real login page.',
        'The page can record your IP address, browser and location, confirming your email address is "live" for future attacks.',
        'Some pages try to download a file automatically or ask you to "update" or "verify" something.',
        'Clicking alone rarely infects an up-to-date device, but it is the first step to the stages below.'
      ]
    });
    if (f.creds || f.link) out.push({
      action: 'Enter your username and password', severity: 'critical',
      steps: [
        'The fake page sends your password straight to the attacker, usually within seconds.',
        'They (or an automated tool) log into your real account, sometimes passing your MFA prompt through in real time ("adversary-in-the-middle").',
        'In a work mailbox they often create hidden inbox rules, read conversations and send new phishing from your trusted address.',
        'If you reuse that password elsewhere, those accounts are now at risk too.'
      ]
    });
    if (f.mfa) out.push({
      action: 'Share the code or approve the sign-in prompt', severity: 'critical',
      steps: [
        'The attacker already has your password. The code is the last thing stopping them.',
        'With your code they sign in immediately and may register their own MFA device so they can return later.',
        'They can then reset other passwords, read email and steal data while appearing to be you.'
      ]
    });
    if (f.file) out.push({
      action: f.macro ? 'Open the attachment and enable macros' : 'Open the attachment', severity: 'critical',
      steps: [
        'The file runs a hidden script or macro that downloads further malware (a "loader").',
        'The loader can steal saved browser passwords and session cookies, or give the attacker remote control.',
        'In business networks this is a common first step towards ransomware: data is stolen, then files are encrypted for a ransom.'
      ]
    });
    if (f.money) out.push({
      action: f.bank ? 'Update the bank details or make the payment' : 'Pay, buy gift cards or share card details', severity: 'critical',
      steps: [
        'Money goes to an account controlled by criminals (often a "money mule").',
        'Within hours it is moved on, withdrawn or converted to crypto, so speed is everything if you need to recover it.',
        'Gift-card codes and crypto transfers are almost impossible to reverse.'
      ]
    });
    if (f.remote || f.callback || f.voice) out.push({
      action: f.remote ? 'Install the remote-access tool' : 'Call back / keep talking', severity: f.remote ? 'critical' : 'high',
      steps: [
        'The "agent" talks you through steps that feel helpful but hand them control.',
        f.remote ? 'Remote-access software lets them see your screen, open your online banking and install malware.' : 'They will usually move on to asking for codes, payments or a remote-access install.',
        'They may hide their activity by asking you to look away or by blanking your screen.'
      ]
    });
    out.push({
      action: 'Reply to the message', severity: f.headers ? 'high' : 'medium',
      steps: [
        'A reply confirms that your address is real and that you are willing to engage.',
        f.headers ? 'The Reply-To or sender address does not match. Your reply goes to the attacker, not the real organisation.' : 'Attackers use your reply to continue the conversation and build trust before the real request.',
        'Never include personal details, codes, or documents in a reply to a suspicious message.'
      ]
    });
    return out;
  }

  // ── Attack path (with MITRE ATT&CK techniques) ────────────────────────────
  function attackPath(report) {
    const f = flags(report);
    const stages = [];
    const delivery = f.voice ? ['T1566.004', 'Phishing: Spearphishing Voice']
      : f.file ? ['T1566.001', 'Phishing: Spearphishing Attachment']
      : f.link ? ['T1566.002', 'Phishing: Spearphishing Link']
      : ['T1566', 'Phishing'];
    stages.push({
      stage: 'Delivery', what: f.voice ? 'The attacker phones you, often with a spoofed caller ID.' : 'The message lands in your inbox, crafted to slip past spam filters.',
      techniques: [delivery], detect: 'Email gateway verdicts, SPF/DKIM/DMARC failures, newly registered sender domains, user reports.'
    });
    stages.push({
      stage: 'Social engineering', what: f.impersonation ? 'They pose as a trusted brand, colleague, boss or authority and add pressure so you act fast.' : 'They use urgency or curiosity to make you act before thinking.',
      techniques: f.impersonation ? [['T1656', 'Impersonation']] : [['T1598', 'Phishing for Information']],
      detect: 'Display-name vs address mismatches, external-sender banners, look-alike domain monitoring.'
    });
    const action = [];
    if (f.link || f.creds) action.push(['T1204.001', 'User Execution: Malicious Link']);
    if (f.file) action.push(['T1204.002', 'User Execution: Malicious File']);
    if (f.remote) action.push(['T1219', 'Remote Access Tools']);
    if (!action.length) action.push(['T1598', 'Phishing for Information']);
    stages.push({ stage: 'Victim action', what: 'You click, open, reply, call back or install. This is the moment the attack depends on.', techniques: action, detect: 'Proxy/DNS logs for the URL, endpoint process creation (e.g. Office spawning PowerShell), RMM tool installs.' });

    const access = [];
    if (f.creds) access.push(['T1056.003', 'Input Capture: Web Portal Capture'], ['T1078', 'Valid Accounts']);
    if (f.mfa) access.push(['T1111', 'Multi-Factor Authentication Interception'], ['T1621', 'MFA Request Generation']);
    if (f.file) access.push(f.macro ? ['T1059.005', 'Command and Scripting Interpreter: Visual Basic'] : ['T1059', 'Command and Scripting Interpreter']);
    if (f.money && !f.creds && !f.file) access.push(['T1656', 'Impersonation']);
    if (access.length) stages.push({ stage: 'Initial access', what: f.file ? 'Malicious code runs on your device.' : f.creds || f.mfa ? 'The attacker logs in to your account using what you gave them.' : 'The attacker gains your trust and a payment channel.', techniques: access, detect: 'Impossible-travel or new-device sign-ins, new MFA method registered, suspicious child processes.' });

    if (f.creds || f.mfa) stages.push({ stage: 'Persistence & spread', what: 'They hide their tracks with inbox rules and use your mailbox to phish your contacts.', techniques: [['T1564.008', 'Hide Artifacts: Email Hiding Rules'], ['T1114.003', 'Email Collection: Email Forwarding Rule'], ['T1534', 'Internal Spearphishing']], detect: 'New inbox/forwarding rules, mass outbound mail, OAuth app consents.' });
    else if (f.file || f.remote) stages.push({ stage: 'Persistence & spread', what: 'Malware or remote access is kept running and spreads to other systems.', techniques: [['T1547', 'Boot or Logon Autostart Execution'], ['T1021', 'Remote Services']], detect: 'EDR alerts, new scheduled tasks/services, lateral movement in authentication logs.' });

    const obj = [];
    if (f.money) obj.push(['T1657', 'Financial Theft']);
    if (f.file || f.remote) obj.push(['T1486', 'Data Encrypted for Impact']);
    if (f.creds || f.mfa || f.file) obj.push(['T1114', 'Email Collection']);
    if (!obj.length) obj.push(['T1589', 'Gather Victim Identity Information']);
    stages.push({ stage: 'Objective', what: f.money ? 'Money is stolen or redirected.' : f.file ? 'Data theft, extortion or ransomware.' : 'Account takeover, data theft and further fraud.', techniques: obj, detect: 'Payment-change verification, DLP alerts, unusual data access volumes.' });
    return stages;
  }

  // ── Recommended actions & incident response ───────────────────────────────
  function actions(report) {
    const f = flags(report);
    const low = report.level === 'Low';
    const now = low ? [
      'Few warning signs were found, but no tool can prove a message is safe.',
      'If it asks you to log in, pay, or open a file, go to the website or contact the sender using details you already trust.',
      'Report it to your IT/security team if anything still feels off.'
    ] : [
      'Do not click links, open attachments, reply, or call numbers in this message.',
      f.voice ? 'Hang up. Call the organisation back on a number you find yourself (back of your card, official website).' : 'Use your email\'s "Report phishing" button, or forward it to your security team as an attachment.',
      'If it claims to be from someone you know, contact them through a separate, trusted channel.',
      'After reporting, delete the message (your security team may ask you to keep it until they confirm).'
    ];

    const ir = [];
    if (f.creds || f.link) ir.push({ title: 'If you entered a password', steps: [
      'Change that password immediately from a device you trust, and anywhere else you reused it.',
      'Sign out of all sessions ("sign out everywhere") and review recent sign-in activity.',
      'Check your MFA methods for any phone or app you do not recognise and remove it.',
      'Look for new inbox rules or forwarding addresses you did not create.',
      'Tell your IT/security team straight away. Minutes matter.'
    ]});
    if (f.mfa) ir.push({ title: 'If you shared a code or approved a prompt', steps: [
      'Change your password now; the attacker almost certainly has it.',
      'Revoke all active sessions and review registered MFA devices.',
      'Report it as a security incident so your team can review sign-in logs.'
    ]});
    if (f.file) ir.push({ title: 'If you opened the attachment', steps: [
      'Disconnect the device from the network (Wi-Fi off / unplug the cable). Do not switch it off. Investigators may need its memory.',
      'Report to IT/security immediately with the file name and the time you opened it.',
      'From a different, clean device, change passwords that were saved in the browser.'
    ]});
    if (f.money) ir.push({ title: 'If you paid or changed bank details', steps: [
      'Call your bank\'s fraud line immediately and ask for a payment recall. The first hours are critical.',
      'Report to your finance team and security team; preserve the email and payment records.',
      'Report to the police / national fraud centre (e.g. Action Fraud in the UK, IC3 in the US, local police in Germany).',
      'Gift cards: contact the card issuer with the codes and receipts right away.'
    ]});
    if (f.remote) ir.push({ title: 'If you installed remote-access software', steps: [
      'Disconnect from the internet and uninstall the tool.',
      'Have the device checked by IT before using online banking or work systems again.',
      'Change important passwords from a different device and warn your bank.'
    ]});
    if (!ir.length) ir.push({ title: 'If you already replied', steps: [
      'Stop the conversation. Do not send anything further.',
      'Tell your security team what you shared, so they can watch for follow-up attacks.',
      'Expect more targeted messages; be extra careful for the next few weeks.'
    ]});

    const soc = [
      'Pull the full message headers and preserve the original (.eml/.msg) as evidence.',
      'Search mail logs for the same sender, subject, URL or attachment across all mailboxes; purge copies.',
      'Block the IOCs below on the email gateway, web proxy/DNS filter and EDR where appropriate.',
      'Review sign-in logs for any user who clicked: new devices, unusual locations, new MFA registrations.',
      'Check for new inbox rules, forwarding and OAuth app consents on affected accounts.',
      'Detonate attachments/URLs in an isolated sandbox. Never on your workstation.',
      'Record a timeline and lessons learned; feed the lure into awareness training.'
    ];
    return { now, ir, soc };
  }

  Object.assign(P, { whatIf, attackPath, actions });
})(typeof window !== 'undefined' ? window : globalThis);
