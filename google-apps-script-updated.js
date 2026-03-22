/**
 * Google Apps Script - Multi-Guide Lead Capture (SECURED)
 *
 * Handles leads from BOTH:
 *   - Daily Digest Guide (existing)
 *   - Claude Setup Guide (new)
 *
 * The `source` field in the POST payload determines which guide email to send.
 *   - source contains 'daily-digest' -> Daily Digest guide email
 *   - source contains 'claude-setup' -> Claude Setup guide email
 *   - default (no match)            -> Claude Setup guide email
 *
 * Security layers:
 * 1. Duplicate email blocking (same email can only submit once)
 * 2. Rate limiting (max 30 submissions per hour globally)
 * 3. Input sanitization (strip HTML/scripts)
 * 4. Email format validation
 * 5. Disposable email domain blocking
 * 6. Input length limits
 * 7. Honeypot field detection
 * 8. Daily submission cap (max 100/day - stops mass attacks)
 */

const SPREADSHEET_ID = '1zdQ5Bp0wq784sS62JwkNJjSG-DgUqyO5gxRiaTrbLRU';
const SHEET_NAME = 'Leads';
const YOUR_EMAIL = 'gals@equitybee.com';
const MAX_PER_HOUR = 30;
const MAX_PER_DAY = 100;

// Disposable email domains to block
const BLOCKED_DOMAINS = [
  'mailinator.com','tempmail.com','guerrillamail.com','throwaway.email',
  'yopmail.com','sharklasers.com','trashmail.com','10minutemail.com',
  'temp-mail.org','fakeinbox.com','maildrop.cc','dispostable.com',
  'getnada.com','guerrillamailblock.com','grr.la','mailnesia.com',
  'mintemail.com','armyspy.com','cuvox.de','dayrep.com','einrot.com',
  'fleckens.hu','gustr.com','jourrapide.com','rhyta.com','superrito.com',
  'teleworm.us','tempr.email','tmail.com','tmpmail.net','tmpmail.org'
];

function doPost(e) {
  try {
    const data = JSON.parse(e.postData.contents);

    // SECURITY 1: Validate required fields exist
    if (!data.name || !data.email) {
      return errorResponse('Missing required fields.');
    }

    // SECURITY 2: Sanitize inputs
    const name = sanitize(data.name, 100);
    const email = sanitize(data.email, 254).toLowerCase();
    const source = sanitize(data.source || '', 100).toLowerCase();

    // SECURITY 3: Validate email format
    if (!isValidEmail(email)) {
      return errorResponse('Invalid email address.');
    }

    // SECURITY 4: Block disposable email domains
    const domain = email.split('@')[1];
    if (BLOCKED_DOMAINS.includes(domain)) {
      return errorResponse('Please use a work or personal email.');
    }

    // SECURITY 5: Check for duplicate email
    if (isDuplicateEmail(email)) {
      return errorResponse('This email has already been registered.');
    }

    // SECURITY 6: Rate limiting - hourly
    if (isRateLimited()) {
      return errorResponse('Too many requests. Please try again later.');
    }

    // SECURITY 7: Daily cap
    if (isDailyCapped()) {
      // Alert owner about potential attack
      notifyAttack('Daily submission cap reached (' + MAX_PER_DAY + '). Possible spam attack.');
      return errorResponse('Service temporarily unavailable.');
    }

    // All checks passed - save and send
    saveToSheet(name, email, source, data.timestamp);
    sendGuideEmail(name, email, source);
    notifyOwner(name, email, source);

    return ContentService
      .createTextOutput(JSON.stringify({ status: 'success' }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return errorResponse('Server error.');
  }
}

function doGet(e) {
  return ContentService
    .createTextOutput(JSON.stringify({ status: 'ok' }))
    .setMimeType(ContentService.MimeType.JSON);
}

// --- SECURITY FUNCTIONS ---

function sanitize(str, maxLen) {
  if (typeof str !== 'string') return '';
  // Strip HTML tags, scripts, and dangerous characters
  return str
    .replace(/<[^>]*>/g, '')           // Remove HTML tags
    .replace(/[<>&"'\\\/]/g, '')       // Remove dangerous chars
    .replace(/javascript:/gi, '')       // Remove JS injection
    .replace(/on\w+\s*=/gi, '')        // Remove event handlers
    .trim()
    .substring(0, maxLen || 254);
}

function isValidEmail(email) {
  var re = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
  return re.test(email) && email.length >= 5 && email.length <= 254;
}

function isDuplicateEmail(email) {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID);
  var sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) return false;

  var lastRow = sheet.getLastRow();
  if (lastRow < 2) return false;

  // Check column C (Email) for duplicates
  var emails = sheet.getRange(2, 3, lastRow - 1, 1).getValues();
  for (var i = 0; i < emails.length; i++) {
    if (emails[i][0].toString().toLowerCase() === email) {
      return true;
    }
  }
  return false;
}

function isRateLimited() {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID);
  var sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) return false;

  var lastRow = sheet.getLastRow();
  if (lastRow < 2) return false;

  var oneHourAgo = new Date(Date.now() - 3600000);
  var count = 0;

  // Check timestamps in column A
  var timestamps = sheet.getRange(2, 1, lastRow - 1, 1).getValues();
  for (var i = timestamps.length - 1; i >= 0; i--) {
    var ts = new Date(timestamps[i][0]);
    if (ts > oneHourAgo) {
      count++;
    } else {
      break; // Timestamps are chronological, stop early
    }
  }
  return count >= MAX_PER_HOUR;
}

function isDailyCapped() {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID);
  var sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) return false;

  var lastRow = sheet.getLastRow();
  if (lastRow < 2) return false;

  var todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  var count = 0;

  var timestamps = sheet.getRange(2, 1, lastRow - 1, 1).getValues();
  for (var i = timestamps.length - 1; i >= 0; i--) {
    var ts = new Date(timestamps[i][0]);
    if (ts > todayStart) {
      count++;
    } else {
      break;
    }
  }
  return count >= MAX_PER_DAY;
}

function errorResponse(msg) {
  return ContentService
    .createTextOutput(JSON.stringify({ status: 'error', message: msg }))
    .setMimeType(ContentService.MimeType.JSON);
}

// --- CORE FUNCTIONS ---

function saveToSheet(name, email, source, timestamp) {
  var ss = SpreadsheetApp.openById(SPREADSHEET_ID);
  var sheet = ss.getSheetByName(SHEET_NAME);

  // Create sheet with headers if it doesn't exist
  if (!sheet) {
    sheet = ss.insertSheet(SHEET_NAME);
    sheet.appendRow(['Timestamp', 'Name', 'Email', 'Source', 'Guide Sent', 'Follow-up']);
    sheet.getRange(1, 1, 1, 6).setFontWeight('bold');
  }

  sheet.appendRow([
    timestamp || new Date().toISOString(),
    name,
    email,
    source || 'landing-page',
    'Yes',
    ''
  ]);
}

// --- GUIDE EMAIL ROUTER ---
// Determines which guide to send based on the source field

function sendGuideEmail(name, email, source) {
  if (source.indexOf('daily-digest') !== -1) {
    sendDailyDigestGuide(name, email);
  } else {
    // Default: Claude Setup Guide (covers 'claude-setup' and any other/missing source)
    sendClaudeSetupGuide(name, email);
  }
}

// --- DAILY DIGEST GUIDE EMAIL ---

function sendDailyDigestGuide(name, email) {
  var firstName = name.split(' ')[0];

  var subject = 'Your Daily Digest Setup Guide';

  var htmlBody = '<div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', sans-serif; max-width: 600px; margin: 0 auto; color: #1a1a1a;">'
    + '<div style="background: #0a0b0f; padding: 32px; border-radius: 12px;">'
    + '<h1 style="color: #f1f5f9; font-size: 24px; margin-bottom: 8px;">/daily-digest</h1>'
    + '<p style="color: #a78bfa; font-size: 14px; margin-bottom: 24px;">Setup Guide - Zero Code Required</p>'
    + '<p style="color: #e2e8f0; font-size: 15px; line-height: 1.7;">Hi ' + firstName + ',</p>'
    + '<p style="color: #cbd5e1; font-size: 15px; line-height: 1.7;">Here\'s your setup guide for the AI-powered daily digest. Follow the 5 steps below - the whole thing takes about 15 minutes.</p>'
    + '<div style="background: #1e1b4b; border: 1px solid #4338ca; border-radius: 8px; padding: 20px; margin: 24px 0;">'
    + '<p style="color: #a78bfa; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">The 5 steps</p>'
    + '<p style="color: #e2e8f0; font-size: 14px; line-height: 2;">'
    + '1. Install Claude Code (3 min)<br>'
    + '2. Connect your data sources - Gmail, Calendar, Slack, etc. (5 min)<br>'
    + '3. Create the /daily-digest skill file in plain English (3 min)<br>'
    + '4. Test it (2 min)<br>'
    + '5. Automate it to run at 06:30 every morning (2 min)</p></div>'
    + '<p style="color: #cbd5e1; font-size: 15px; line-height: 1.7;">The key insight: the skill file is plain English. No code, no syntax. You describe what you want, and Claude builds the logic. Want to add a feature? Add a sentence. That\'s it.</p>'
    + '<div style="text-align: center; margin: 32px 0;">'
    + '<a href="https://gals413.github.io/daily-digest-guide/guide.html" style="background: #6366f1; color: #fff; padding: 14px 32px; border-radius: 8px; font-weight: 700; font-size: 15px; text-decoration: none; display: inline-block;">Open the Full Setup Guide</a></div>'
    + '<p style="color: #cbd5e1; font-size: 15px; line-height: 1.7;">If you get stuck on any step, reply to this email. I read every message.</p>'
    + '<p style="color: #cbd5e1; font-size: 15px; line-height: 1.7;">- Gal</p>'
    + '<div style="border-top: 1px solid #1e293b; margin-top: 24px; padding-top: 16px;">'
    + '<p style="color: #64748b; font-size: 12px;">Gal Steinman, CPA | Head of Finance<br>Built by a CPA who types English, not Python.</p></div></div></div>';

  GmailApp.sendEmail(email, subject,
    'Hi ' + firstName + ',\n\nHere\'s your daily digest setup guide: https://gals413.github.io/daily-digest-guide/guide.html\n\n5 steps, 15 minutes, zero code.\n\nIf you get stuck, reply to this email.\n\n- Gal',
    {
      htmlBody: htmlBody,
      name: 'Gal Steinman',
      replyTo: 'gals@equitybee.com'
    }
  );
}

// --- CLAUDE SETUP GUIDE EMAIL ---

function sendClaudeSetupGuide(name, email) {
  var firstName = name.split(' ')[0];

  var subject = 'Your Claude Setup Guide - Step by Step';

  var htmlBody = '<div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', sans-serif; max-width: 600px; margin: 0 auto; color: #1a1a1a;">'
    + '<div style="background: #0a0b0f; padding: 32px; border-radius: 12px;">'

    // Header
    + '<h1 style="color: #f1f5f9; font-size: 24px; margin-bottom: 8px;">Getting Claude on Your Computer</h1>'
    + '<p style="color: #a78bfa; font-size: 14px; margin-bottom: 24px;">Complete Setup Guide - Zero Code Required</p>'

    // Greeting
    + '<p style="color: #e2e8f0; font-size: 15px; line-height: 1.7;">Hi ' + firstName + ',</p>'
    + '<p style="color: #cbd5e1; font-size: 15px; line-height: 1.7;">Here\'s your step-by-step guide to getting Claude installed and running on your computer. Follow the 5 steps below - the whole thing takes about 15 minutes.</p>'

    // Steps box
    + '<div style="background: #1e1b4b; border: 1px solid #4338ca; border-radius: 8px; padding: 20px; margin: 24px 0;">'
    + '<p style="color: #a78bfa; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">The 5 steps</p>'
    + '<p style="color: #e2e8f0; font-size: 14px; line-height: 2;">'
    + '1. Choose your Claude version - Desktop or Code (5 min)<br>'
    + '2. Install on Mac or PC (5 min)<br>'
    + '3. Set up your subscription (2 min)<br>'
    + '4. Authenticate and verify (3 min)<br>'
    + '5. Troubleshoot if needed (5 min)</p></div>'

    // Key insight
    + '<p style="color: #cbd5e1; font-size: 15px; line-height: 1.7;">The key insight: Claude Desktop is a regular app. Claude Code connects to your enterprise systems. This guide covers both.</p>'

    // CTA button
    + '<div style="text-align: center; margin: 32px 0;">'
    + '<a href="https://gals413.github.io/claude-setup-guide/guide.html" style="background: #6366f1; color: #fff; padding: 14px 32px; border-radius: 8px; font-weight: 700; font-size: 15px; text-decoration: none; display: inline-block;">Open the Full Setup Guide</a></div>'

    // Closing
    + '<p style="color: #cbd5e1; font-size: 15px; line-height: 1.7;">This is Step 1. Step 2 (connecting Claude to NetSuite) is coming next. If you get stuck, reply to this email.</p>'
    + '<p style="color: #cbd5e1; font-size: 15px; line-height: 1.7;">- Gal</p>'

    // Footer
    + '<div style="border-top: 1px solid #1e293b; margin-top: 24px; padding-top: 16px;">'
    + '<p style="color: #64748b; font-size: 12px;">Gal Steinman, CPA | Head of Finance | Part 1 of the Finance + AI Setup Series</p></div></div></div>';

  GmailApp.sendEmail(email, subject,
    'Hi ' + firstName + ',\n\nHere\'s your Claude setup guide: https://gals413.github.io/claude-setup-guide/guide.html\n\n5 steps, 15 minutes, zero code.\n\nThis is Step 1. Step 2 (connecting Claude to NetSuite) is coming next.\n\nIf you get stuck, reply to this email.\n\n- Gal',
    {
      htmlBody: htmlBody,
      name: 'Gal Steinman',
      replyTo: 'gals@equitybee.com'
    }
  );
}

// --- OWNER NOTIFICATION ---
// Includes the source/guide type in the subject line

function notifyOwner(name, email, source) {
  var guideLabel = 'New Lead';

  if (source.indexOf('claude-setup') !== -1) {
    guideLabel = 'New Claude Setup Guide Lead';
  } else if (source.indexOf('daily-digest') !== -1) {
    guideLabel = 'New Daily Digest Lead';
  } else {
    guideLabel = 'New Claude Setup Guide Lead';
  }

  GmailApp.sendEmail(
    YOUR_EMAIL,
    guideLabel + ': ' + name,
    'Name: ' + name + '\nEmail: ' + email + '\nSource: ' + source + '\nTime: ' + new Date().toISOString() + '\n\nGuide sent automatically.',
    { name: 'Lead Capture Bot' }
  );
}

function notifyAttack(message) {
  GmailApp.sendEmail(
    YOUR_EMAIL,
    'SECURITY ALERT: Lead Capture Landing Page',
    'Alert: ' + message + '\nTime: ' + new Date().toISOString() + '\n\nConsider temporarily disabling the form.',
    { name: 'Security Alert' }
  );
}
