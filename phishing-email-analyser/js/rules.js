/*
 * rules.js — the "knowledge base" of the Phishing Email Analyser.
 *
 * Plain-English summary:
 *   Each rule describes ONE warning sign that phishing messages commonly use.
 *   A rule has:
 *     - id        : a short internal name
 *     - skill     : which training topic it belongs to (used for scores & training)
 *     - title     : the name shown to the user
 *     - weight    : how strongly this sign points to phishing (higher = more suspicious)
 *     - modes     : whether it applies to emails, voice-call transcripts, or both
 *     - patterns  : "regular expressions", a mini-language for describing text
 *                   patterns. /\burgent\b/i means "the word urgent, any capitals".
 *     - explain   : why this matters, in plain English
 *
 * Nothing in this file sends data anywhere. It is just a list of patterns.
 */
(function (root) {
  'use strict';

  // Training topics ("skills"). Every rule maps to one of these.
  const SKILLS = {
    pressure:      { name: 'Urgency & pressure',            short: 'Pressure' },
    credentials:   { name: 'Password & credential theft',   short: 'Credentials' },
    mfa:           { name: 'MFA & verification-code theft', short: 'MFA codes' },
    money:         { name: 'Payment, invoice & bank fraud', short: 'Payments' },
    impersonation: { name: 'Impersonation & authority',     short: 'Impersonation' },
    links:         { name: 'Suspicious links & URLs',       short: 'Links' },
    attachments:   { name: 'Dangerous attachments & macros', short: 'Attachments' },
    vishing:       { name: 'Voice phishing (vishing)',       short: 'Vishing' },
    headers:       { name: 'Sender & header forgery',        short: 'Headers' }
  };

  const BOTH = ['email', 'voice'];

  const TEXT_RULES = [
    // ── Pressure ────────────────────────────────────────────────────────────
    {
      id: 'urgency', skill: 'pressure', weight: 12, modes: BOTH,
      title: 'Urgency and pressure language',
      patterns: [
        /\burgent(ly)?\b/gi, /\bimmediate(ly)?\b/gi, /\bas soon as possible\b|\basap\b/gi,
        /\bwithin (the next )?\d+\s*(hours?|hrs?|minutes?|mins?|days?)\b/gi,
        /\b(act|respond|reply|verify|confirm|update) now\b/gi, /\b(today|tonight) only\b/gi,
        /\bby (the )?end of (the )?(day|business)\b/gi, /\bfinal (notice|warning|reminder)\b/gi,
        /\blast chance\b/gi, /\btime[- ]sensitive\b/gi, /\bdon'?t delay\b/gi, /\bright away\b/gi,
        /\bexpires? (today|tonight|soon|in \d+)\b/gi, /\bbefore it'?s too late\b/gi,
        /\bpay now\b/gi, /\b(verify|confirm|update|updated|pay|paid|respond|reply|complete|completed|re-?register|sign in|log ?in)\b[^.\n]{0,40}\bby \d{1,2}([:.]\d{2}|\s?(am|pm))\b/gi, /\b(must|required to|need to|have to)\b[^.\n]{0,40}\b(today|tonight)\b/gi
      ],
      explain: 'Attackers create a sense of urgency so you act before you think. Real organisations rarely demand action within minutes or hours.'
    },
    {
      id: 'threat', skill: 'pressure', weight: 15, modes: BOTH,
      title: 'Threat of account suspension, closure or penalties',
      patterns: [
        /\b(accounts?|mailbox(es)?|access|service|subscription|card)\b[^.\n]{0,40}\b(suspend(ed)?|suspension|locked|closed|closure|terminated|deactivated|disabled|blocked|restricted|cancell?ed)\b/gi,
        /\b(suspend|lock|close|terminate|deactivate|disable|block|restrict)\w*\b[^.\n]{0,25}\byour (account|mailbox|access|card)\b/gi,
        /\blegal action\b|\blawsuit\b|\barrest warrant\b|\bwarrant for your arrest\b|\bpenalt(y|ies)\b|\bbe fined\b/gi,
        /\bunauthori[sz]ed (access|activity|login|log-in|sign-?in|transaction|purchase)\b/gi,
        /\bunusual (sign-?in|activity|login|log-in)\b/gi, /\bpermanently (deleted|lost|removed)\b/gi,
        /\bfailure to (comply|respond|verify|update|act)\b/gi
      ],
      explain: 'Threatening to close your account, delete your data or involve the police is a classic way to frighten you into clicking or paying.'
    },

    // ── Credentials ─────────────────────────────────────────────────────────
    {
      id: 'password-request', skill: 'credentials', weight: 25, modes: BOTH,
      title: 'Request for your password or login details',
      patterns: [
        /\b(confirm|verify|update|validate|re-?enter|provide|send|share|enter|type|give|tell)\b[^.\n]{0,40}\b(password|passcode|login details|log-in details|credentials|sign-?in details|online banking pin|pin)\b/gi,
        /\b(password|credentials)\b[^.\n]{0,30}\b(expire[sd]?|expiring|will be reset|reset required)\b/gi,
        /\bverify your (account|identity|mailbox|email|e-mail)\b/gi,
        /\b(log ?in|sign ?in)\b[^.\n]{0,30}\bto (verify|confirm|restore|unlock|keep|reactivate|avoid)\b/gi,
        /\bsecurity (questions?|answers?)\b/gi
      ],
      explain: 'Legitimate services never ask you to send or "confirm" your password by email, text or phone. This is the most common goal of phishing: stealing your login so the attacker can take over the account.'
    },

    // ── MFA ─────────────────────────────────────────────────────────────────
    {
      id: 'mfa-request', skill: 'mfa', weight: 25, modes: BOTH,
      title: 'Request for an MFA / verification code',
      patterns: [
        /\b(send|share|give|read|tell|forward|reply with|provide|confirm|repeat)\b[^.\n]{0,40}\b(code|otp|passcode|one[- ]time (password|pin))\b/gi,
        /\bcode\b[^.\n]{0,30}\b(we (just )?sent|you (just )?(got|received)|sent to your (phone|mobile|device|number))\b/gi,
        /\b(approve|accept|tap yes on|press yes on)\b[^.\n]{0,30}\b(push|prompt|request|notification|sign-?in request|login request)\b/gi,
        /\bre-?regist(er|ration)\b[^.\n]{0,30}\b(mfa|2fa|authenticator|two-factor)\b|\b(mfa|2fa|authenticator|two-factor)\b[^.\n]{0,30}\bre-?regist/gi
      ],
      explain: 'Multi-factor authentication (MFA) codes exist to stop attackers who already know your password. Anyone asking you to share a code, or approve a login you did not start, is trying to get past that last line of defence.'
    },

    // ── Money ───────────────────────────────────────────────────────────────
    {
      id: 'payment', skill: 'money', weight: 22, modes: BOTH,
      title: 'Payment, gift-card or crypto request',
      patterns: [
        /\bgift ?cards?\b/gi, /\b(itunes|apple|google play|steam|amazon|ebay|vanilla) (gift )?cards?\b/gi,
        /\bscratch (off )?(the )?(back|code|panel)\b/gi, /\b(wire|bank|telegraphic) transfer\b/gi,
        /\b(bitcoin|btc|cryptocurrency|crypto|usdt|tether|ethereum|wallet address)\b/gi,
        /\b(urgent|immediate|quick|same-day) (payment|transfer|wire)\b/gi,
        /\bpay(ment)?\b[^.\n]{0,30}\b(immediately|right now|overdue|outstanding)\b/gi,
        /\bwestern union\b|\bmoneygram\b/gi, /\b(unpaid|outstanding|pending) (customs |delivery |shipping |redelivery |postage )?(fee|charge|duty|toll)s?\b/gi, /\b(process|make|send|arrange) (a|the) (payment|transfer|wire)\b/gi
      ],
      explain: 'Requests to buy gift cards, send crypto or make a rushed transfer are hard to reverse. Criminals prefer them because the money is gone almost instantly.'
    },
    {
      id: 'bank-change', skill: 'money', weight: 28, modes: BOTH,
      title: 'Request to change bank or payment details',
      patterns: [
        /\b(change|update|new|changed|updated|amend)\b[^.\n]{0,40}\b(bank (details|account|information|info)|account (number|details)|payment (details|information|instructions)|banking (details|information)|iban|sort code|routing number|remittance details)\b/gi,
        /\b(our|my) (bank|account) (has )?(changed|is changing)\b/gi,
        /\bdo not (use|pay (to|into)) the (old|previous)\b/gi,
        /\b(direct deposit|payroll)\b[^.\n]{0,40}\b(change|update)\b/gi
      ],
      explain: 'Changing where money is sent is the heart of Business Email Compromise (BEC), one of the costliest cybercrimes. Always confirm bank-detail changes by phoning a number you already trust, never one in the email.'
    },
    {
      id: 'invoice', skill: 'money', weight: 12, modes: ['email'],
      title: 'Invoice or payment-due language',
      patterns: [
        /\binvoices?\b/gi, /\boutstanding (balance|payment|amount)\b/gi, /\boverdue\b/gi,
        /\bpayment (is )?(due|pending|failed|declined)\b/gi, /\bpurchase order\b/gi, /\bbilling statement\b/gi,
        /\bremittance advice\b/gi
      ],
      explain: 'Fake invoices rely on you assuming someone else ordered something. If you were not expecting this invoice, verify it with the supplier using contact details you already have.'
    },
    {
      id: 'prize', skill: 'money', weight: 14, modes: BOTH,
      title: 'Too-good-to-be-true offer (prize, refund, inheritance)',
      patterns: [
        /\byou('ve| have)? (won|been selected|been chosen)\b/gi, /\bcongratulations\b/gi, /\blottery\b/gi,
        /\bclaim your (prize|reward|refund|gift|bonus)\b/gi, /\bunclaimed (funds|refund|package|parcel)\b/gi,
        /\btax refund\b/gi, /\binheritance\b/gi, /\bfree (gift|iphone|ipad)\b/gi
      ],
      explain: 'Unexpected rewards play on excitement. The "prize" usually requires your card details, a small fee, or a login.'
    },

    // ── Impersonation ───────────────────────────────────────────────────────
    {
      id: 'brand', skill: 'impersonation', weight: 6, modes: BOTH,
      title: 'Mentions a commonly impersonated organisation',
      patterns: [
        /\b(microsoft|office ?365|microsoft 365|outlook|onedrive|sharepoint|paypal|apple id|icloud|amazon|netflix|dhl|fedex|ups|royal mail|deutsche post|docusign|dropbox|google|gmail|linkedin|facebook|instagram|whatsapp|wells fargo|hsbc|barclays|chase|bank of america|sparkasse|irs|hmrc|finanzamt|tax office|revenue service|coinbase|binance)\b/gi,
        /\b(it|helpdesk|help desk|service desk|technical support|tech support|security|payroll|hr) (team|department|desk)\b/gi, /\b(it service desk|it support|it helpdesk|it help desk)\b/gi
      ],
      explain: 'Attackers pretend to be brands and departments people already trust. A familiar name is not proof the message is real; check the actual sender address and link destinations.'
    },
    {
      id: 'authority', skill: 'impersonation', weight: 16, modes: BOTH,
      title: 'Executive or authority pressure',
      patterns: [
        /\b(ceo|cfo|coo|managing director|chief executive|the director|president)\b[^.\n]{0,60}\b(request(ed)?|asked|needs?|urgent|favou?r|confidential)\b/gi,
        /\bare you (available|at your desk|free)\b/gi, /\b(quick|small|urgent) favou?r\b/gi, /\bi need you to\b/gi
      ],
      explain: 'Messages that appear to come from a senior manager exploit our instinct to obey authority. "Are you at your desk? I need a quick favour" is the opening line of many gift-card and wire-fraud scams.'
    },
    {
      id: 'secrecy', skill: 'impersonation', weight: 14, modes: BOTH,
      title: 'Request for secrecy or unusual unavailability',
      patterns: [
        /\bkeep (this|it) (confidential|between us|secret|private|quiet)\b/gi,
        /\b(don'?t|do not) (tell|mention|discuss|share this with|inform)\b/gi, /\bstrictly confidential\b/gi,
        /\b(in a meeting|travel(l)?ing|on a flight|in a conference)\b[^.\n]{0,40}\b(can'?t|cannot|unable to) (talk|call|take calls|speak)\b/gi
      ],
      explain: 'Asking you to keep a request secret, or saying the sender cannot be phoned, stops you from doing the one thing that would expose the scam: checking with someone else.'
    },
    {
      id: 'generic-greeting', skill: 'impersonation', weight: 6, modes: ['email'],
      title: 'Generic greeting instead of your name',
      patterns: [
        /^\s*(dear|hello|hi)\s+(customer|user|client|member|account holder|sir\/madam|sir or madam|valued customer|valued member|beneficiary|friend|e-?mail user|mailbox user)\b/gim
      ],
      explain: 'Bulk phishing is sent to thousands of people, so it often uses a vague greeting. Companies you have an account with usually know your name.'
    },

    // ── Links (text-based lures) ────────────────────────────────────────────
    {
      id: 'click-lure', skill: 'links', weight: 8, modes: ['email'],
      title: 'Pushes you to click a link or open a file',
      patterns: [
        /\bclick (here|the (link|button) below|below|on the link)\b/gi, /\b(log ?in|sign ?in) (here|below|now)\b/gi,
        /\bopen the (attached|attachment)\b/gi, /\bdownload (the )?(attached|file|document)\b/gi,
        /\bscan (the|this) qr code\b/gi
      ],
      explain: 'The call-to-action is where the attack happens. Hover over (do not click) links to see where they really go, or visit the site by typing its address yourself.'
    },
    {
      id: 'callback', skill: 'vishing', weight: 15, modes: ['email'],
      title: 'Asks you to call a phone number (callback phishing)',
      patterns: [
        /\b(call|contact|phone|ring) (us|our (support|billing|helpline|team)|the (support|billing) team|customer (support|service))\b[^.\n]{0,30}\+?\d[\d\s().-]{7,}\d/gi,
        /\bif you did not (make|authori[sz]e|request) this\b[^.\n]{0,60}\bcall\b/gi
      ],
      explain: 'Callback phishing ("TOAD", telephone-oriented attack delivery) contains no malicious link at all. Instead it gets you to phone a scammer, who then talks you into installing remote-access software or paying.'
    },

    // ── Attachments & macros (text-based) ───────────────────────────────────
    {
      id: 'macros', skill: 'attachments', weight: 30, modes: ['email'],
      title: 'Asks you to enable macros or editing',
      patterns: [
        /\benable (the )?(content|editing|macros?)\b/gi, /\bmacros?\b/gi, /\bprotected view\b/gi,
        /\b(document|file) (is |was )?(protected|encrypted|secured)\b[^.\n]{0,60}\b(enable|click|password)\b/gi
      ],
      explain: 'Office macros are small programs inside documents. Attackers ask you to "Enable Content" because that is what lets their malicious code run on your computer.'
    },

    // ── Voice phishing specific ─────────────────────────────────────────────
    {
      id: 'remote-access', skill: 'vishing', weight: 30, modes: BOTH,
      title: 'Request to install remote-access software',
      patterns: [
        /\b(anydesk|teamviewer|quick ?assist|screenconnect|connectwise|logmein|ultraviewer|supremo|rustdesk|splashtop)\b/gi,
        /\bremote (access|desktop|support|session)\b/gi,
        /\b(install|download)\b[^.\n]{0,30}\b(app|application|software|program|tool)\b[^.\n]{0,40}\b(so (that )?(i|we) can|to let (me|us)|for me to)\b/gi
      ],
      explain: 'Remote-access tools hand control of your computer to the caller. Fake "IT support" and "bank fraud team" callers use them to steal data, install malware or log into your bank.'
    },
    {
      id: 'safe-account', skill: 'vishing', weight: 30, modes: BOTH,
      title: '"Safe account" or money-protection story',
      patterns: [
        /\bsafe (account|wallet)\b/gi,
        /\b(move|transfer)\b[^.\n]{0,30}\b(your )?(money|funds|savings|balance)\b[^.\n]{0,40}\b(protect|secure|safe|safety)\b/gi
      ],
      explain: 'No genuine bank or police force will ever ask you to move money to a "safe account". This is one of the most common and damaging phone scams.'
    },
    {
      id: 'caller-authority', skill: 'vishing', weight: 18, modes: ['voice'],
      title: 'Caller claims to be from a bank, police, IT or government',
      patterns: [
        /\b(fraud|security|investigations?) (department|team|unit|division)\b/gi,
        /\b(police|officer|detective|fbi|europol|interpol|customs|court|tax (office|authority)|irs|hmrc|finanzamt)\b/gi,
        /\b(calling|call) (you )?from (your bank|the bank|microsoft|apple|amazon|the (tax|revenue)|it|the it department|the helpdesk|the help desk|support)\b/gi
      ],
      explain: 'Caller ID can be faked ("spoofed"), so a call that appears to come from your bank may not. Hang up and call back on the number printed on your card or the official website.'
    },
    {
      id: 'stay-on-line', skill: 'vishing', weight: 16, modes: ['voice'],
      title: 'Keeps you on the line / discourages hanging up',
      patterns: [/\b(stay|remain) on the (line|phone|call)\b/gi, /\b(don'?t|do not) hang up\b/gi, /\b(don'?t|do not) (call|contact) (your|the) bank\b/gi],
      explain: 'Scammers keep you on the phone so you cannot pause, think, or call the real organisation to check.'
    },
    {
      id: 'card-details', skill: 'vishing', weight: 25, modes: BOTH,
      title: 'Asks for card numbers, CVV or PIN',
      patterns: [/\b(card number|long number on (the front|your card)|cvv|cvc|security code on the back|three[- ]digit code|expiry date|pin number)\b/gi],
      explain: 'Your full card number, CVV and PIN are never needed by someone who is calling to help you. Sharing them lets the caller spend your money.'
    }
  ];

  // Ordered checklist used in the awareness challenge ("which red flags did you spot?")
  const FLAG_CHOICES = [
    { id: 'pressure',     label: 'Urgency or threats' },
    { id: 'credentials',  label: 'Asks for password / login' },
    { id: 'mfa',          label: 'Asks for an MFA code' },
    { id: 'money',        label: 'Payment, gift card or bank change' },
    { id: 'impersonation',label: 'Impersonates a brand or boss' },
    { id: 'links',        label: 'Suspicious link' },
    { id: 'attachments',  label: 'Risky attachment / macros' },
    { id: 'headers',      label: 'Sender address doesn\'t match' }
  ];

  // Domains that shorten links and hide the real destination.
  const SHORTENERS = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly','cutt.ly','shorturl.at','tiny.cc','rb.gy','bit.do','t.ly','s.id','lnkd.in','qrco.de','short.io','bl.ink','v.gd','tr.im','shorte.st','adf.ly','soo.gd','clck.ru','urlz.fr','surl.li'];

  // Top-level domains that are cheap and frequently abused (not automatically malicious).
  const RISKY_TLDS = ['zip','mov','top','xyz','click','link','work','gq','tk','ml','cf','ga','cam','rest','country','kim','support','icu','cyou','sbs','monster','buzz','quest','live','shop','online','site','fit','loan'];

  // Free hosting / form builders that are legitimate but widely abused for phishing pages.
  const ABUSED_HOSTS = ['web.app','firebaseapp.com','pages.dev','workers.dev','r2.dev','netlify.app','vercel.app','glitch.me','000webhostapp.com','weebly.com','wixsite.com','sites.google.com','forms.gle','herokuapp.com','onrender.com','ngrok.io','ngrok-free.app','blogspot.com','godaddysites.com','webflow.io','typedream.app','ipfs.io','dweb.link','github.io','surge.sh','framer.website','storage.googleapis.com','windows.net','azurewebsites.net'];

  // Free webmail providers (a "company" writing from these is suspicious).
  const FREE_MAIL = ['gmail.com','googlemail.com','outlook.com','hotmail.com','live.com','yahoo.com','ymail.com','aol.com','gmx.com','gmx.de','gmx.net','web.de','proton.me','protonmail.com','icloud.com','mail.com','yandex.com','zoho.com','t-online.de'];

  // Brand → official registered domains. Used to spot fakes like "paypal-secure.xyz".
  const BRANDS = {
    paypal:    ['paypal.com','paypal.me'],
    microsoft: ['microsoft.com','live.com','office.com','office365.com','outlook.com','microsoftonline.com','sharepoint.com','onedrive.com','msft.net','azure.com','windows.com','skype.com','bing.com'],
    office:    ['office.com','office365.com','microsoft.com'],
    outlook:   ['outlook.com','live.com','microsoft.com','office.com'],
    apple:     ['apple.com','icloud.com','me.com'],
    icloud:    ['icloud.com','apple.com'],
    amazon:    ['amazon.com','amazon.co.uk','amazon.de','amazon.fr','amazon.it','amazon.es','amazon.ca','amazon.in','amazon.co.jp','amazon.com.au','amazonaws.com','aws.amazon.com','primevideo.com'],
    netflix:   ['netflix.com'],
    google:    ['google.com','gmail.com','youtube.com','googleusercontent.com','google.de','google.co.uk','goo.gl','g.co'],
    dhl:       ['dhl.com','dhl.de','dhl.co.uk'],
    fedex:     ['fedex.com'],
    docusign:  ['docusign.com','docusign.net'],
    dropbox:   ['dropbox.com','dropboxusercontent.com'],
    linkedin:  ['linkedin.com','lnkd.in'],
    facebook:  ['facebook.com','fb.com','meta.com'],
    instagram: ['instagram.com'],
    wellsfargo:['wellsfargo.com'],
    chase:     ['chase.com'],
    hsbc:      ['hsbc.com','hsbc.co.uk'],
    barclays:  ['barclays.co.uk','barclays.com'],
    sparkasse: ['sparkasse.de'],
    coinbase:  ['coinbase.com'],
    binance:   ['binance.com'],
    adobe:     ['adobe.com'],
    steam:     ['steampowered.com','steamcommunity.com'],
    irs:       ['irs.gov'],
    hmrc:      ['gov.uk']
  };

  // Second-level suffixes, so "evil.co.uk" is treated as one registered domain.
  const MULTI_SUFFIXES = ['co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.jp','co.nz','com.br','co.za','com.mx','co.in','com.tr','com.cn','com.sg','com.hk','co.kr'];

  // File types and why they are risky.
  const ATTACHMENT_TYPES = {
    executable: { weight: 35, exts: ['exe','scr','pif','bat','cmd','vbs','vbe','js','jse','wsf','wsh','hta','msi','msp','ps1','jar','cpl','lnk','reg','dll','appx','msix','scf','inf','apk','dmg','pkg','sh','py'],
      title: 'Executable or script attachment', explain: 'This file type runs code the moment it is opened. Legitimate businesses almost never email programs or scripts.' },
    container:  { weight: 20, exts: ['iso','img','vhd','vhdx'],
      title: 'Disk-image attachment', explain: 'Disk images (ISO/IMG) are used to smuggle malware past email filters and Windows "Mark of the Web" warnings.' },
    macro:      { weight: 25, exts: ['docm','xlsm','pptm','dotm','xltm','xlam','ppam','xlsb'],
      title: 'Macro-enabled Office document', explain: 'Files ending in "m" can contain macros, small programs that attackers use to install malware.' },
    archive:    { weight: 12, exts: ['zip','rar','7z','cab','gz','tar','ace','arj'],
      title: 'Compressed archive attachment', explain: 'Archives (especially password-protected ones) hide their contents from security scanners. Be careful what is inside.' },
    html:       { weight: 20, exts: ['html','htm','shtml','xhtml','mht','svg'],
      title: 'HTML or SVG attachment', explain: 'An HTML/SVG attachment opens a web page stored on your own computer. It is a common way to show a fake login page that email filters cannot scan as a link.' },
    onenote:    { weight: 20, exts: ['one'],
      title: 'OneNote attachment', explain: 'OneNote files have been widely abused to hide malicious scripts behind a fake "Click to view" button.' }
  };

  root.PEA = root.PEA || {};
  Object.assign(root.PEA, { SKILLS, TEXT_RULES, FLAG_CHOICES, SHORTENERS, RISKY_TLDS, ABUSED_HOSTS, FREE_MAIL, BRANDS, MULTI_SUFFIXES, ATTACHMENT_TYPES });
})(typeof window !== 'undefined' ? window : globalThis);
