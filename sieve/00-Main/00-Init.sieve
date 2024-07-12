# Docs:
#   Sieve: https://tools.ietf.org/html/rfc5228
#   Sieve Extensions: https://www.iana.org/assignments/sieve-extensions/sieve-extensions.xhtml

require [ "variables", "include" ];

### Global Variable ###
global [ "WORK_ADDR" ];
set "WORK_ADDR" "ggabrielli@suse.de";

### Global Flag ###
global [ "RSS2EMAIL", "CHANGEDETECTION", "MAILINGLIST" ];
set "RSS2EMAIL"         "rss2email";
set "CHANGEDETECTION"   "changedetection";
set "MAILINGLIST"       "mailinglist";

include :personal "10-rss2email.sieve";
include :personal "11-changedetection.sieve";
include :personal "12-mailinglist.sieve";

# Any email which reach this point will be deliverd within the Inbox folder.
