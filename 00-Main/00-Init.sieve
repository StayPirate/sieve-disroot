# Sieve: https://tools.ietf.org/html/rfc5228
# Sieve Extensions: https://www.iana.org/assignments/sieve-extensions/sieve-extensions.xhtml
require [ "variables", "include" ];

### Variables ###
#
global [ "DISROOT_ADDR", "USERNAME", "NAME" ];
set "DISROOT_ADDR" "crazybyte@disroot.org";
set "USERNAME" "crazybyte";
set "NAME" "gianluca";
set "SECURITY_TEAM_ADDR" "security-team@suse.de";

### IMAP System Flags (Tags) ###
# IMAP system flags are specified at
# https://datatracker.ietf.org/doc/html/rfc3501#section-2.3.2
# Usually: \Answered \Flagged \Draft \Deleted \Seen \Recent
### IMAP Custom Flags (Tags) ###
# Custom flags are available if the IMAP server enable them.
# In order to check if your server allows you to use them, you can check if
# \* is present in the PERMANENTFLAGS setting.
# E.g:
#     * OK [PERMANENTFLAGS (\Answered \Flagged \Draft \Deleted \Seen \*)]
# You can get this info connecting to your imap server via cmdline, you can
# use the openssl cmdline utility for that:
#     > openssl s_client -connect imap-int.suse.de:993
#
global [ "FLAG_DUPLICATED", "FLAG_MUTED", "FLAG_BETA", "FLAG_DIRECT" ];
set "FLAG_DUPLICATED"     "duplicated";
set "FLAG_MUTED"          "muted";
set "FLAG_BETA"           "BETA_RULE";
set "FLAG_DIRECT"         "direct";

# Feeds
include :personal "40-crazybyte-security-feed.sieve";