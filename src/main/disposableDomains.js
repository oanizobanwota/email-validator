"use strict";

// Common throw-away / temporary mailbox providers. Extend freely.
const DISPOSABLE_DOMAINS = new Set([
  "10minutemail.com", "10minutemail.net", "10minemail.com", "20minutemail.com", "33mail.com",
  "anonbox.net", "anonymbox.com", "binkmail.com", "bobmail.info", "burnermail.io",
  "byom.de", "chammy.info", "crazymailing.com", "cuvox.de", "dayrep.com",
  "deadaddress.com", "despam.it", "discard.email", "dispostable.com", "disposableemailaddresses.com",
  "dodgeit.com", "dontreg.com", "dropmail.me", "dump-email.info", "e4ward.com",
  "einrot.com", "emailondeck.com", "emailsensei.com", "emailtemporario.com.br", "emltmp.com",
  "ephemail.net", "fakeinbox.com", "fakemail.fr", "fakemailgenerator.com", "fleckens.hu",
  "getairmail.com", "getnada.com", "gishpuppy.com", "grr.la", "guerrillamail.biz",
  "guerrillamail.com", "guerrillamail.de", "guerrillamail.info", "guerrillamail.net", "guerrillamail.org",
  "guerrillamailblock.com", "gustr.com", "harakirimail.com", "haltospam.com", "hidemail.de",
  "imgof.com", "inboxalias.com", "inboxbear.com", "incognitomail.org", "jetable.org",
  "jourrapide.com", "kasmail.com", "klzlk.com", "koszmail.pl", "kurzepost.de",
  "lroid.com", "mail-temporaire.fr", "mail.tm", "mail7.io", "mailcatch.com",
  "maildrop.cc", "maileater.com", "mailexpire.com", "mailforspam.com", "mailimate.com",
  "mailinator.com", "mailinator.net", "mailinator2.com", "mailme.lv", "mailnesia.com",
  "mailnull.com", "mailsac.com", "mailtemp.info", "mailtothis.com", "mailzilla.com",
  "meltmail.com", "mintemail.com", "mohmal.com", "moakt.com", "mt2015.com",
  "mytemp.email", "mytrashmail.com", "nada.email", "nomail.xl.cx", "nospam.ze.tc",
  "nospamfor.us", "nowmymail.com", "objectmail.com", "obobbo.com", "oneoffemail.com",
  "onewaymail.com", "owlpic.com", "pookmail.com", "proxymail.eu", "rcpt.at",
  "rhyta.com", "rtrtr.com", "safetymail.info", "sharklasers.com", "shieldemail.com",
  "sogetthis.com", "spam4.me", "spamavert.com", "spambox.us", "spamex.com",
  "spamfree24.org", "spamgourmet.com", "spamhereplease.com", "spaml.com", "spammotel.com",
  "superrito.com", "tafmail.com", "teleworm.us", "temp-mail.org", "temp-mail.io",
  "tempail.com", "tempemail.co", "tempemail.net", "tempinbox.com", "tempmail.com",
  "tempmail.de", "tempmail.net", "tempmailo.com", "tempomail.fr", "temporaryemail.net",
  "temporaryinbox.com", "tempr.email", "throwam.com", "throwawaymail.com", "tmail.ws",
  "tmailinator.com", "trash-mail.com", "trash-mail.de", "trashmail.com", "trashmail.de",
  "trashmail.me", "trashmail.net", "trashymail.com", "trbvm.com", "tyldd.com",
  "uggsrock.com", "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org", "wh4f.org",
  "yopmail.com", "yopmail.fr", "yopmail.net", "zetmail.com", "zoemail.net",
]);

module.exports = { DISPOSABLE_DOMAINS };
