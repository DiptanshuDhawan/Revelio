// PhishGuard AI — Sample Emails
// Five complete, realistic demo emails for testing and demonstration.

'use strict';

export const SAMPLE_EMAILS = [
  // ─────────────────────────────────────────────────────────────────────────
  // 1. Classic Phishing — Fake PayPal Account Suspension
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'classic-phishing',
    label: '🪤 Classic Phishing',
    description: 'Fake PayPal urgent account suspension notice',
    content: `From: "PayPal Security Team" <security@paypa1-support.com>
To: customer@example.com
Reply-To: noreply@paypa1-support.com
Subject: ⚠️ URGENT: Your PayPal Account Has Been Suspended - Immediate Action Required
Date: Thu, 21 May 2026 08:14:22 -0500
Message-ID: <20260521081422.paypa1.fake@paypa1-support.com>
X-Mailer: PhishKit Pro 4.2
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail

Dear Customer,

We have detected unusual activity on your PayPal account. To protect your account and prevent unauthorized access, we have temporarily limited your account access.

Your account will be permanently suspended within 24 hours unless you verify your identity immediately.

ACCOUNT DETAILS:
Account Status: SUSPENDED
Reason: Unusual login attempt detected from: Russia (84.201.xxx.xxx)
Date Detected: May 21, 2026

To restore your account access, you must verify your information immediately by clicking the button below:

<a href="http://paypa1-secure-verification.xyz/restore?ref=SUP923&token=abc123def456">Verify My Account Now</a>

You will need to confirm:
• Full name and date of birth
• Social security number (last 4 digits)
• Credit card number and CVV
• Current password and new PIN

Failure to respond immediately will result in permanent account closure and a hold on all pending payments.

This is your FINAL NOTICE.

Sincerely,
PayPal Security Department
PayPal Holdings, Inc.
2211 North First Street, San Jose, CA 95131

© 2026 PayPal, Inc. All rights reserved.

Note: Please do not reply to this email. Replies are not monitored.`,
  },

  // ─────────────────────────────────────────────────────────────────────────
  // 2. AI-Generated BEC — Fake CEO Invoice Payment
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'bec-ceo-fraud',
    label: '🏢 CEO Fraud (BEC)',
    description: 'Fake CEO requesting urgent invoice payment to new account',
    content: `From: "Robert Harrington" <robert.harrington@gmail.com>
To: sarah.chen@acmecorp.com
Subject: Urgent - Confidential Wire Transfer Required
Date: Thu, 21 May 2026 11:43:07 -0400
Message-ID: <20260521114307.bec@gmail.com>

Sarah,

I need you to process an urgent wire transfer today. I'm currently in a board meeting in Singapore and cannot be reached by phone. This is time-sensitive and must be completed before end of business today.

A supplier, Meridian Consulting Group, requires final payment on invoice #MCG-2026-0449 for $87,500. Due to our recent bank account update, please use the following wire details instead of the ones on file:

Bank Name: Apex Financial Partners LLC
Account Number: 9847261053
Routing Number: 082736401
Reference: INV-MCG-2026-0449-FINAL

Please process this immediately and send me a confirmation once the wire has been initiated. Do not discuss this with anyone else in the office — this is a confidential vendor arrangement approved at the board level.

I will personally confirm receipt once I'm out of the meeting.

Best regards,
Robert Harrington
CEO, Acme Corporation

Sent from my iPhone`,
  },

  // ─────────────────────────────────────────────────────────────────────────
  // 3. Spear Phishing — IT Helpdesk Credential Reset for Acme Corp
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'spear-phishing-it',
    label: '🎯 Spear Phishing (IT)',
    description: 'Targeted IT helpdesk credential reset phishing for Acme Corp employees',
    content: `From: "Acme Corp IT Support" <it-helpdesk@acme-corp-support.net>
To: john.williams@acmecorp.com
Reply-To: tickets@acme-corp-support.net
Subject: [ACME-TICKET #84721] Mandatory Password Reset - Microsoft 365 Account
Date: Thu, 21 May 2026 09:22:15 -0500
Message-ID: <ACME-84721@acme-corp-support.net>
X-Originating-IP: 185.234.219.45

Dear John Williams,

As part of Acme Corporation's ongoing security infrastructure upgrade (Project Horizon - Phase 2), all employees in the Engineering and Finance departments are required to reset their Microsoft 365 credentials by May 23, 2026.

Our security systems have flagged your account (john.williams@acmecorp.com) as requiring immediate attention. Failure to complete this process by the deadline will result in your account being locked and loss of access to all corporate resources including:

• Microsoft Teams and Outlook
• SharePoint and OneDrive
• VPN and Remote Desktop access
• Internal project management tools

RESET YOUR PASSWORD NOW:
<a href="http://acmecorp-m365-portal.click/reset?user=john.williams&dept=engineering&token=XK29qL">https://portal.microsoftonline.com/acmecorp/reset</a>

You will need your current password to complete the reset process.

IT Support Team
Acme Corporation — Help Desk
Ticket ID: ACME-84721
Priority: HIGH
Opened by: IT Security Operations

This message was sent automatically. Reply to this email to update your support ticket.`,
  },

  // ─────────────────────────────────────────────────────────────────────────
  // 4. Malware Delivery — Fake FedEx Delivery Notification
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'malware-fedex',
    label: '📦 Malware (FedEx Fake)',
    description: 'Malware delivery via fake FedEx package notification with executable',
    content: `From: "FedEx Delivery Services" <deliveries@fedex-tracking-alert.ru>
To: recipient@example.com
Subject: FedEx: Package Delivery Failed - Action Required (Tracking: 7489234019283)
Date: Thu, 21 May 2026 14:05:33 +0000
Message-ID: <fedex.fake.20260521@fedex-tracking-alert.ru>
X-Mailer: Outlook Express 6.0

Dear Valued Customer,

A delivery attempt was made for your package today, but we were unable to complete the delivery due to an incorrect address.

SHIPMENT DETAILS:
Tracking Number: 7489234019283
Sender: Amazon Fulfillment Center
Estimated Value: $342.00
Status: DELIVERY FAILED — CUSTOMS HOLD

To reschedule your delivery and release your package from our customs facility, you must download and complete the attached customs declaration form.

IMPORTANT: The package will be returned to sender and destroyed after 48 hours if you do not complete this process.

Attached File: FedEx_CustomsForm_7489234019283.pdf.exe

Please download the attachment, open it, and follow the instructions to complete your customs declaration. You may need to temporarily disable your antivirus software if you receive a security warning — this is normal for digitally signed government forms.

For support, call our customer service line or reply to this email.

FedEx International Delivery Support
© 2026 FedEx Corporation. All Rights Reserved.
1000 FedEx Drive, Memphis, TN 38116`,
  },

  // ─────────────────────────────────────────────────────────────────────────
  // 5. Legitimate Email — Real Google Security Alert (Safe for Contrast)
  // ─────────────────────────────────────────────────────────────────────────
  {
    id: 'legitimate-google',
    label: '✅ Legitimate (Google)',
    description: 'Genuine Google security alert — safe email for contrast testing',
    content: `From: "Google" <no-reply@accounts.google.com>
To: yourname@gmail.com
Reply-To: no-reply@accounts.google.com
Return-Path: <no-reply@accounts.google.com>
Subject: Security alert - new sign-in on Windows
Date: Thu, 21 May 2026 07:33:12 +0000
Message-ID: <CAH3v=GoogLe.real20260521@accounts.google.com>
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=accounts.google.com; dkim=pass header.i=@accounts.google.com; dmarc=pass

Hi,

Your Google Account (yourname@gmail.com) was just used to sign in from a new Windows device.

Sign-in Details:
• Time: Thursday, May 21, 2026, 7:33 AM UTC
• Device: Windows PC (Chrome Browser)
• Location: New York, NY, USA

If this was you:
You don't need to do anything. This email is just to let you know about the new sign-in.

If this wasn't you:
Your account may have been compromised. Please secure your account immediately by visiting:
https://accounts.google.com/signin/v2/recoveryidentifier

To review your recent account activity:
https://myaccount.google.com/notifications

You're receiving this email to let you know about important activity on your account.

© 2026 Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043, USA`,
  },
];

export function getSampleById(id) {
  return SAMPLE_EMAILS.find((s) => s.id === id) || null;
}
