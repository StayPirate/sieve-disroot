require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include", "imap4flags", "body", "regex" ];

global [ "CHANGEDETECTION" ];

if header :is "X-Application" "changedetection.io" {

#   ██╗    ██╗███████╗███████╗██╗  ██╗██╗  ██╗   ██╗    ██╗   ██╗██████╗ ██████╗  █████╗ ████████╗███████╗
#   ██║    ██║██╔════╝██╔════╝██║ ██╔╝██║  ╚██╗ ██╔╝    ██║   ██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔════╝
#   ██║ █╗ ██║█████╗  █████╗  █████╔╝ ██║   ╚████╔╝     ██║   ██║██████╔╝██║  ██║███████║   ██║   █████╗  
#   ██║███╗██║██╔══╝  ██╔══╝  ██╔═██╗ ██║    ╚██╔╝      ██║   ██║██╔═══╝ ██║  ██║██╔══██║   ██║   ██╔══╝  
#   ╚███╔███╔╝███████╗███████╗██║  ██╗███████╗██║       ╚██████╔╝██║     ██████╔╝██║  ██║   ██║   ███████╗
#    ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝        ╚═════╝ ╚═╝     ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝

    #### TODO:
    #### In order to *only* get security-related article from LWN I could use
    #### this page: https://lwn.net/headlines/text via changedetection.
    #### Or use the rss feed (view-source:https://lwn.net/headlines/newrss) and
    #### filter for "security" in either "Subject" and "Body".

#   ██████╗ ██╗      ██████╗  ██████╗ 
#   ██╔══██╗██║     ██╔═══██╗██╔════╝ 
#   ██████╔╝██║     ██║   ██║██║  ███╗
#   ██╔══██╗██║     ██║   ██║██║   ██║
#   ██████╔╝███████╗╚██████╔╝╚██████╔╝
#   ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ 

    # NotSoSecure Blog
    # https://notsosecure.com/technical
    if header :contains "Subject" "NotSoSecure" {
        fileinto :create "Feed.Blog.NotSoSecure";
        stop;
    }

#   ███████╗███████╗ ██████╗     █████╗ ██████╗ ██╗   ██╗██╗███████╗ ██████╗ ██████╗ ██╗   ██╗
#   ██╔════╝██╔════╝██╔════╝    ██╔══██╗██╔══██╗██║   ██║██║██╔════╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
#   ███████╗█████╗  ██║         ███████║██║  ██║██║   ██║██║███████╗██║   ██║██████╔╝ ╚████╔╝ 
#   ╚════██║██╔══╝  ██║         ██╔══██║██║  ██║╚██╗ ██╔╝██║╚════██║██║   ██║██╔══██╗  ╚██╔╝  
#   ███████║███████╗╚██████╗    ██║  ██║██████╔╝ ╚████╔╝ ██║███████║╚██████╔╝██║  ██║   ██║   
#   ╚══════╝╚══════╝ ╚═════╝    ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   

    # rule:[Curl]
    # https://curl.se/docs/security.html
    if header :contains "Subject" "Curl" {
        fileinto :create "Feed.SA.Curl";
        stop;
    }

    # rule:[Android Security Bulletin]
    # https://source.android.com/docs/security/bulletin/asb-overview
    if header :contains "Subject" "Android Security Bulletin" {
        fileinto :create "Feed.SA.Android";
        stop;
    }

    # rule:[Shibboleth SA]
    # https://shibboleth.net/community/advisories/
    if header :contains "Subject" "shibboleth-sp SA" {
        fileinto :create "Feed.SA.Shibboleth";
        stop;
    }

    # rule:[Dovecot SA]
    # https://www.dovecot.org/security/
    if header :contains "Subject" "Dovecot SA" {
        fileinto :create "Feed.SA.Dovecot";
        stop;
    }

    # rule:[Qualys SA]
    # https://www.qualys.com/research/security-advisories/
    if header :contains "Subject" "Qualys SA" {
        fileinto :create "Feed.SA.Qualys";
        stop;
    }

    # rule:[AMD SA]
    # https://www.amd.com/en/resources/product-security.html#security
    if header :contains "Subject" "AMD SA" {
        fileinto :create "Feed.SA.AMD";
        stop;
    }

    # rule:[Postgresql SA]
    # https://www.postgresql.org/support/security/
    if header :contains "Subject" "Postgresql SA" {
        fileinto :create "Feed.SA.Postgresql";
        stop;
    }

#   ██████╗ ███████╗██╗     ███████╗ █████╗ ███████╗███████╗
#   ██╔══██╗██╔════╝██║     ██╔════╝██╔══██╗██╔════╝██╔════╝
#   ██████╔╝█████╗  ██║     █████╗  ███████║███████╗█████╗  
#   ██╔══██╗██╔══╝  ██║     ██╔══╝  ██╔══██║╚════██║██╔══╝  
#   ██║  ██║███████╗███████╗███████╗██║  ██║███████║███████╗
#   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝

    # rule:[Chromium]
    # https://chromiumdash.appspot.com/releases?platform=Linux
    if header :contains "Subject" "Chromium releases" {
        fileinto :create "Feed.Release.Chromium";
        stop;
    }

    # rule:[Thunderbird]
    # https://www.thunderbird.net/en-US/thunderbird/releases
    if header :contains "Subject" "Thunderbird" {
        fileinto :create "Feed.Release.Thunderbird";
        stop;
    }

#    ██████╗ ████████╗██╗  ██╗███████╗██████╗ 
#   ██╔═══██╗╚══██╔══╝██║  ██║██╔════╝██╔══██╗
#   ██║   ██║   ██║   ███████║█████╗  ██████╔╝
#   ██║   ██║   ██║   ██╔══██║██╔══╝  ██╔══██╗
#   ╚██████╔╝   ██║   ██║  ██║███████╗██║  ██║
#    ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

    # If the email did not match any of the above rules, then trash it. But flag it first,
    # so looking in the trash folder I can undestand from where the email was deleted.
    addflag "${CHANGEDETECTION}";
    fileinto :create "Trash";
    stop;

}