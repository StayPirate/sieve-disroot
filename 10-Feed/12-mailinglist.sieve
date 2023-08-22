### TODO: subscribe to all of the following ML and create related filter

# require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include", "imap4flags", "body", "regex" ];

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

    # RedHat Security Advisories (RHSA) are gotten by the rhsa-announce ML.
    # RHSA:         https://listman.redhat.com/mailman/listinfo/rhsa-announce

    # openSUSE Security Update (openSUSE-SU/SUSE-SU) are fetched from the security-announce ML.
    # If the update is shipped to both openSUSE and SUSE, then the name is SUSE-SU, while if
    # it's exclusive for openSUSE it is named openSUSE-SU.
    # openSUSE-SU:  https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org

    # SUSE Security Update (SUSE-SU) are fetched from the sle-security-updates ML.
    # It also notify about "SUSE Container Update Advisory" and "SUSE Image Update Advisory" as well. 
    # SUSE-SU:      https://lists.suse.com/mailman/listinfo/sle-security-updates

    # Arch Linux Security Advisory (ASA) are fetched from the arch-security ML.
    # ASA:          https://lists.archlinux.org/listinfo/arch-security

    # Gentoo Linux Security Advisories (GLSA) are fetched from the gentoo-announce ML.
    # GLSA:         https://security.gentoo.org/glsa

    # Slackware Security Advisories (SSA) are fetched from the slackware-security ML.
    # SSA:          http://www.slackware.com/lists/archive/

    # Oracle Linux Security Advisories (ELSA) are fetched from the el-errata ML.
    # ELSA:         https://oss.oracle.com/mailman/listinfo/el-errata

    # Jenkins SA are fetched from the osss ML.
    # http://oss-security.openwall.org/wiki/mailing-lists/oss-security

    # Xen SA (XSA) are fetched from the xen-announce ML.
    # https://lists.xenproject.org/cgi-bin/mailman/listinfo/xen-announce

    # Weechat SA are fetched from the weechat-security ML.
    # https://lists.nongnu.org/mailman/listinfo/weechat-security

    # OpenJDK Vulnerability Advisory are fetched from the vuln-announce ML.
    # https://mail.openjdk.org/mailman/listinfo/vuln-announce

    # Tomcat SA are fetched from the tomcat ML
    # https://lists.apache.org/list?announce@tomcat.apache.org

#   ██████╗ ███████╗██╗     ███████╗ █████╗ ███████╗███████╗
#   ██╔══██╗██╔════╝██║     ██╔════╝██╔══██╗██╔════╝██╔════╝
#   ██████╔╝█████╗  ██║     █████╗  ███████║███████╗█████╗  
#   ██╔══██╗██╔══╝  ██║     ██╔══╝  ██╔══██║╚════██║██╔══╝  
#   ██║  ██║███████╗███████╗███████╗██║  ██║███████║███████╗
#   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝

    # Nmap/Npcap announcements are fetched from the nmap announce ML.
    # https://nmap.org/mailman/listinfo/announce

#   ███╗   ██╗███████╗██╗    ██╗███████╗    ██╗     ███████╗████████╗████████╗███████╗██████╗ 
#   ████╗  ██║██╔════╝██║    ██║██╔════╝    ██║     ██╔════╝╚══██╔══╝╚══██╔══╝██╔════╝██╔══██╗
#   ██╔██╗ ██║█████╗  ██║ █╗ ██║███████╗    ██║     █████╗     ██║      ██║   █████╗  ██████╔╝
#   ██║╚██╗██║██╔══╝  ██║███╗██║╚════██║    ██║     ██╔══╝     ██║      ██║   ██╔══╝  ██╔══██╗
#   ██║ ╚████║███████╗╚███╔███╔╝███████║    ███████╗███████╗   ██║      ██║   ███████╗██║  ██║
#   ╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝ ╚══════╝    ╚══════╝╚══════╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝

    # Linux Foundation
    # https://linuxfoundation.org

    # CyberSaiyan (ITA)
    # https://cybersaiyan.us17.list-manage.com
