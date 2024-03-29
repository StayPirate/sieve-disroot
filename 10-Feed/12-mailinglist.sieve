### TODO: subscribe to all of the following ML and create related filter

require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include", "imap4flags", "body", "regex" ];

global [ "MAILINGLIST" ];

#   ███████╗███████╗ ██████╗     █████╗ ██████╗ ██╗   ██╗██╗███████╗ ██████╗ ██████╗ ██╗   ██╗
#   ██╔════╝██╔════╝██╔════╝    ██╔══██╗██╔══██╗██║   ██║██║██╔════╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
#   ███████╗█████╗  ██║         ███████║██║  ██║██║   ██║██║███████╗██║   ██║██████╔╝ ╚████╔╝ 
#   ╚════██║██╔══╝  ██║         ██╔══██║██║  ██║╚██╗ ██╔╝██║╚════██║██║   ██║██╔══██╗  ╚██╔╝  
#   ███████║███████╗╚██████╗    ██║  ██║██████╔╝ ╚████╔╝ ██║███████║╚██████╔╝██║  ██║   ██║   
#   ╚══════╝╚══════╝ ╚═════╝    ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝  

    # rule:[Debian - security announce]
    # Fetching Debian Security Advisories (DSA) from the debian-security-announce ML, bc
    # it provides more detailed information compared to the DSA RSS-feed.
    # DSA ML:       https://lists.debian.org/debian-security-announce/
    # DSA RSS-feed: https://www.debian.org/security/dsa
    if header :contains "List-Id" "<debian-security-announce.lists.debian.org>" {
        fileinto :create "Feed.SA.Distro.Debian";
        stop;
    }

    # rule:[Ubuntu - security announce]
    # Ubuntu Security Notice (USN) are fetched from the ubuntu-security-announce ML.
    # https://lists.ubuntu.com/mailman/listinfo/ubuntu-security-announce
    if header :contains "List-Id" "<ubuntu-security-announce.lists.ubuntu.com>" {
        fileinto :create "Feed.SA.Distro.Ubuntu";
        stop;
    }

    # rule:[RedHat - security announce]
    # RedHat Security Advisories (RHSA) are fetched from the rhsa-announce ML.
    # https://listman.redhat.com/mailman/listinfo/rhsa-announce
    if header :contains "List-Id" "<rhsa-announce.redhat.com>" {
        fileinto :create "Feed.SA.Distro.RedHat";
        stop;
    }

    # rule:[OpenSUSE - security-announce]
    # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/
    if header :contains "List-Id" "<security-announce.lists.opensuse.org>" {
        fileinto :create "Feed.SA.Distro.openSUSE";
        stop;
    }

    # rule:[sle-security-updates]
    # https://lists.suse.com/mailman/listinfo/sle-security-updates
    if header :contains "List-Id" "<sle-security-updates.lists.suse.com>" {
        if body :contains "SUSE Container Update Advisory" {
            fileinto :create "Feed.SA.Distro.SUSE.container";
        }
        elsif body :contains "SUSE Image Update Advisory" {
            fileinto :create "Feed.SA.Distro.SUSE.image";
        }
        else {
            fileinto :create "Feed.SA.Distro.SUSE";
        }
        stop;
    }

    # rule:[Archlinux - arch-security]
    # Archlinux Security Advisory (ASA) are fetched from the arch-security ML.
    # https://lists.archlinux.org/listinfo/arch-security
    if header :contains "List-Id" "<arch-security.lists.archlinux.org>" {
        fileinto :create "Feed.SA.Distro.Archlinux";
        stop;
    }

    # rule:[Gentoo Linux Security Advisories - gentoo-announce]
    # Gentoo Linux Security Advisories (GLSA) are fetched from the gentoo-announce ML.
    # https://www.gentoo.org/support/security/
    if header :contains "List-Id" "<gentoo-announce.gentoo.org>" {
        fileinto :create "Feed.SA.Distro.Gentoo";
        stop;
    }

    # rule:[Slackware - slackware-security]
    # Slackware Security Advisories (SSA) are fetched from the slackware-security ML.
    # http://www.slackware.com/lists/archive/
    if address :is "To" "slackware-security@slackware.com" {
        fileinto :create "Feed.SA.Distro.Slackware";
        stop;
    }

    # rule:[Oracle Linux SA - ELSA]
    # Oracle Linux Security Advisories (ELSA) are fetched from the el-errata ML.
    # https://oss.oracle.com/mailman/listinfo/el-errata
    if header :contains "List-Id" "<el-errata.oss.oracle.com>" {
        fileinto :create "Feed.SA.Distro.Oracle";
        stop;
    }

    # Jenkins SA are fetched from the osss ML.
    # http://oss-security.openwall.org/wiki/mailing-lists/oss-security

    # rule:[Xen SA - XSA]
    # Xen SA (XSA) are fetched from the xen-announce ML.
    # https://lists.xenproject.org/cgi-bin/mailman/listinfo/xen-announce
    if header :contains "List-Id" "<xen-announce.lists.xenproject.org>" {
        if not header :contains "Subject" "security" {
            # Tag it, so it will be trashed.
            addflag "${MAILINGLIST}";
        }
        else {
            fileinto :create "Feed.SA.Xen";
            stop;
        }
    }

    # rule:[SA - weechat]
    # Weechat SA are fetched from the weechat-security ML.
    # https://lists.nongnu.org/mailman/listinfo/weechat-security
    if header :contains "List-Id" "<weechat-security.nongnu.org>" {
        fileinto :create "Feed.SA.Weechat";
        stop;
    }

    # rule:[OpenJDK SA]
    # OpenJDK Vulnerability Advisory are fetched from the vuln-announce ML.
    # https://mail.openjdk.org/mailman/listinfo/vuln-announce
    if header :contains "List-Id" "<vuln-announce.openjdk.org>" {
        fileinto :create "Feed.SA.OpenJDK";
        stop;
    }

    # rule:[Tomcat SA]
    # Tomcat SA are fetched from the tomcat ML
    # https://lists.apache.org/list?announce@tomcat.apache.org
    if header :contains "List-Id" "<announce.tomcat.apache.org>" {
        if header :contains "Subject" "[SECURITY]" { 
            fileinto :create "Feed.SA.Tomcat";
        } else {
            discard;
        }
        stop;
    }

#   ██████╗ ███████╗██╗     ███████╗ █████╗ ███████╗███████╗
#   ██╔══██╗██╔════╝██║     ██╔════╝██╔══██╗██╔════╝██╔════╝
#   ██████╔╝█████╗  ██║     █████╗  ███████║███████╗█████╗  
#   ██╔══██╗██╔══╝  ██║     ██╔══╝  ██╔══██║╚════██║██╔══╝  
#   ██║  ██║███████╗███████╗███████╗██║  ██║███████║███████╗
#   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝

    # rule:[Seclist - nmap announce]
    # Nmap/Npcap announcements are fetched from the nmap announce ML.
    # https://nmap.org/mailman/listinfo/announce
    if header :contains "List-Id" "<announce.nmap.org>" {
        fileinto :create "Feed.Release.Nmap";
        stop;
    }

#   ███╗   ██╗███████╗██╗    ██╗███████╗    ██╗     ███████╗████████╗████████╗███████╗██████╗ 
#   ████╗  ██║██╔════╝██║    ██║██╔════╝    ██║     ██╔════╝╚══██╔══╝╚══██╔══╝██╔════╝██╔══██╗
#   ██╔██╗ ██║█████╗  ██║ █╗ ██║███████╗    ██║     █████╗     ██║      ██║   █████╗  ██████╔╝
#   ██║╚██╗██║██╔══╝  ██║███╗██║╚════██║    ██║     ██╔══╝     ██║      ██║   ██╔══╝  ██╔══██╗
#   ██║ ╚████║███████╗╚███╔███╔╝███████║    ███████╗███████╗   ██║      ██║   ███████╗██║  ██║
#   ╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝ ╚══════╝    ╚══════╝╚══════╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝

    # Linux Foundation
    # https://linuxfoundation.org

    # rule:[NL - CyberSaiyan]
    # https://cybersaiyan.us17.list-manage.com
    if anyof( header :contains "X-campaignid" "mailchimpf988b10b57d02d9e7119d186a",
              header :contains "X-Campaign" "mailchimpf988b10b57d02d9e7119d186a" ) {
        fileinto :create "Feed.News Letter.CyberSaiyan";
        addflag "italian";
        stop;
    }

#    ██████╗ ████████╗██╗  ██╗███████╗██████╗ 
#   ██╔═══██╗╚══██╔══╝██║  ██║██╔════╝██╔══██╗
#   ██║   ██║   ██║   ███████║█████╗  ██████╔╝
#   ██║   ██║   ██║   ██╔══██║██╔══╝  ██╔══██╗
#   ╚██████╔╝   ██║   ██║  ██║███████╗██║  ██║
#    ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

    # Trash all the emails matching the ${MAILINGLIST} flag. I add this flag on the above rules
    # to tag emails coming from MLs that need to be trashed.
    if hasflag :contains "${MAILINGLIST}" {
        fileinto :create "Trash";
        stop;
    }