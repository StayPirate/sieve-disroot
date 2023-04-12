require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include", "imap4flags", "body" ];

set "WORK_ADDR" "ggabrielli@suse.de";

###################################
##### CRAZYBYTE SECURITY FEED #####
###################################
# Notifications are generated by a rss2email daemon. Source code and configuration
# can be found here: https://github.com/StayPirate/rss2email
#
# Feed
# ├── Weekly update
# │   ├── SSD
# │   ├── LWN
# │   └── AT&T
# ├── Blog
# │   ├── TOR
# │   ├── Mozilla
# │   ├── Thunderbird
# │   ├── Github
# │   ├── Microsoft
# │   ├── Chromium
# │   ├── Chrome
# │   ├── Google
# │   ├── Project Zero
# │   ├── Cloudflare
# │   ├── Sentinelone
# │   ├── Intezer
# │   ├── Avast
# │   ├── Good Reads
# │   ├── Activism
# │   ├── MiaMammaUsaLinux
# │   └── Guerredirete
# ├── Ezine
# │   ├── AppSec
# │   ├── POCorGTFO
# │   └── Uninformed
# ├── SA
# │   ├── Distro
# │   │   ├── Debian
# │   │   ├── Ubuntu
# │   │   ├── RedHat
# │   │   ├── SUSE
# │   │   │   ├── container
# │   │   │   └── image
# │   │   ├── openSUSE
# │   │   ├── Gentoo
# │   │   ├── Fedora
# │   │   ├── Slackware
# │   │   ├── Archlinux
# │   │   └── Oracle
# │   ├── Github
# │   ├── Mozilla
# │   ├── OpenWRT
# │   ├── PowerDNS
# │   ├── Rust
# │   ├── Drupal
# │   ├── Tomcat
# │   ├── Jenkins
# │   ├── Nmap
# │   ├── Xen
# │   ├── OpenJDK
# │   ├── Weechat
# │   ├── TOR
# │   ├── VLC
# │   └── GCP
# ├── Release
# │   ├── Podman
# │   ├── KeePassXC
# │   ├── ClamAV
# │   ├── Chrome
# │   ├── Unifi Controller
# │   ├── Foot
# │   ├── Apple
# │   ├── SUSE Tools
# │   └── ucode
# │       └── Intel
# ├── News Letter
# │   ├── CyberSaiyan
# │   └── Linux Foundation
# ├── News
# │   ├── Crypto Scam
# │   ├── Breaches
# │   └── Archlinux
# └── Podcast
#     ├── Ubuntu Security
#     ├── Darknet Diaries
#     ├── Thundebird
#     ├── Fossified
#     ├── Open Source Security
#     └── Dayzerosec

if header :is "X-RSS-Instance" "crazybyte-security-feed" {

    # rule:[convert X-RSS-Tags to IMAP-flags]
    # This rule takes the whole string in the header X-RSS-Tags and use it to set IMAP-flags.
    # The string is expected to be either a single word or multiple words separated by a single space.
    if exists "X-RSS-Tags" {
        if header :matches "X-RSS-Tags" "*" {
            addflag "${1}";
        }
    }

#   ██╗    ██╗███████╗███████╗██╗  ██╗██╗  ██╗   ██╗    ██╗   ██╗██████╗ ██████╗  █████╗ ████████╗███████╗
#   ██║    ██║██╔════╝██╔════╝██║ ██╔╝██║  ╚██╗ ██╔╝    ██║   ██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔════╝
#   ██║ █╗ ██║█████╗  █████╗  █████╔╝ ██║   ╚████╔╝     ██║   ██║██████╔╝██║  ██║███████║   ██║   █████╗  
#   ██║███╗██║██╔══╝  ██╔══╝  ██╔═██╗ ██║    ╚██╔╝      ██║   ██║██╔═══╝ ██║  ██║██╔══██║   ██║   ██╔══╝  
#   ╚███╔███╔╝███████╗███████╗██║  ██╗███████╗██║       ╚██████╔╝██║     ██████╔╝██║  ██║   ██║   ███████╗
#    ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝        ╚═════╝ ╚═╝     ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝

    # rule:[SSD Secure Disclosure]
    # https://www.youtube.com/channel/UC9ZnYbYqOe6Y3eRdw0TMz9Q
    if header :is "X-RSS-Feed" "https://www.youtube.com/channel/UC9ZnYbYqOe6Y3eRdw0TMz9Q" {
        fileinto :create "Feed.Weekly update.SSD";
        stop;
    }

    # rule:[AT&T Youtube tech channel]
    # https://www.youtube.com/channel/UCnpDurxReTSpFs5-AhDo8Kg
    if header :is "X-RSS-Feed" "https://www.youtube.com/channel/UCnpDurxReTSpFs5-AhDo8Kg" {
        fileinto :create "Feed.Weekly update.AT&T";
        stop;
    }

    #### TODO # In order to only get security-related article from LWN I could use
    #### TODO # this page: https://lwn.net/headlines/text, but I need to use urlwatch.

#   ██████╗ ██╗      ██████╗  ██████╗ 
#   ██╔══██╗██║     ██╔═══██╗██╔════╝ 
#   ██████╔╝██║     ██║   ██║██║  ███╗
#   ██╔══██╗██║     ██║   ██║██║   ██║
#   ██████╔╝███████╗╚██████╔╝╚██████╔╝
#   ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ 

    # rule:[Chromium Blog (security)]
    # http://blog.chromium.org
    if allof ( header :contains "X-RSS-Feed" "blog.chromium.org",
               header :contains "Keywords" "security" ) {
        fileinto :create "Feed.Blog.Chromium";
        stop;
    }

    # rule:[Chrome Blog (security)]
    # http://security.googleblog.com/
    if header :contains "X-RSS-Feed" "http://security.googleblog.com/" {
        fileinto :create "Feed.Blog.Chrome";
        stop;
    }

    # rule:[Google Blog (security)]
    # https://blog.google
    if allof ( header :is "X-RSS-Feed" "https://blog.google/",
               header :contains "Keywords" "security" ) {
        fileinto :create "Feed.Blog.Google";
        stop;
    }

    # rule:[Microsoft Security Blog]
    # https://www.microsoft.com/security/blog
    if header :is "X-RSS-Feed" [ "https://www.microsoft.com/security/blog",
                                 "https://www.microsoft.com/en-us/security/blog/" ] {
        fileinto :create "Feed.Blog.Microsoft";
        stop;
    }

    # rule:[Microsoft Security Response Center Blog]
    # https://msrc-blog.microsoft.com
    if header :is "X-RSS-Feed" "https://msrc-blog.microsoft.com" {
        fileinto :create "Feed.Blog.Microsoft";
        stop;
    }

    # rule:[GitHub Security Blog]
    # https://github.blog/category/security/feed/
    if header :contains "X-RSS-Feed" "https://github.blog" {
        fileinto :create "Feed.Blog.Github";
        stop;
    }

    # rule:[Mozilla Security Blog]
    # https://blog.mozilla.org/security
    if header :is "X-RSS-Feed" "https://blog.mozilla.org/security" {
        fileinto :create "Feed.Blog.Mozilla";
        stop;
    }

    # rule:[TOR blog]
    # https://blog.torproject.org/
    # Ignore release notifications
    if allof (  header :is "X-RSS-Feed" "https://blog.torproject.org/",
                not header :contains "Subject" "New",
                not header :contains "Subject" "Release:" ) {
        fileinto :create "Feed.Blog.TOR";
        stop;
    }

    # rule:[Guerre di rete]
    # https://guerredirete.substack.com
    if header :is "X-RSS-Feed" "https://guerredirete.substack.com" {
        fileinto :create "Feed.Blog.Guerredirete";
        addflag "italian";
        stop;
    }

    # rule:[MiaMammaUsaLinux]
    # https://www.miamammausalinux.org
    if header :is "X-RSS-Feed" "https://www.miamammausalinux.org" {
        fileinto :create "Feed.Blog.MiaMammaUsaLinux";
        addflag "italian";
        stop;
    }

    # rule:[Stackoverflow]
    # Essays, opinions, and advice on the act of computer programming from Stack Overflow.
    # https://stackoverflow.blog
    if header :is "X-RSS-Feed" "https://stackoverflow.blog" {
        if header :contains "Keywords" "security" {
            fileinto :create "Feed.Blog.Stackoverflow";
            stop;
        }
    }

    # rule:[Justin Steven SA]
    # https://github.com/justinsteven/advisories
    if header :is "X-RSS-Feed" "https://github.com/justinsteven/advisories/commits/main" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Cryptography Dispatches]
    # Cryptography Dispatches by Filippo Valsorda (AKA FiloSottile)
    # old blog: https://buttondown.email/cryptography-dispatches
    # new blog: https://words.filippo.io
    if header :is "X-RSS-Feed" "https://words.filippo.io/" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[0pointer]
    # Lennart Poettering personal blog
    # https://0pointer.net/blog
    if header :is "X-RSS-Feed" "https://0pointer.net/blog/" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # Grapl Security
    # https://www.graplsecurity.com/subscribe

    # rule:[Hermes Press]
    # Center for Transparency and Digital Human Rights
    # https://www.hermescenter.org/press/
    if header :is "X-RSS-Feed" "https://www.hermescenter.org" {
        fileinto :create "Feed.Blog.Activism";
        addflag "italian";
        stop;
    }

    # rule:[copernicani]
    # https://www.copernicani.it
    if allof ( header :is "X-RSS-Feed" "https://www.copernicani.it",
               header :contains "Keywords" [ "cybersecurity", "cyberwarfare" ] ) {
        fileinto :create "Feed.Blog.Activism";
        addflag "italian";
        stop;
    }

    # rule:[Sentinelone]
    # https://sentinelone.com/blog/
    if allof (  header :contains "X-RSS-Feed" "sentinelone.com",
                header :contains "Keywords" [ "security", "cybercrime", "malware", "escape" ] ) {

                    # They use Cloudflare CDN which in turn redirects (302) to the italian
                    # blog (it.sentinelone.com) if the request comes from an italian IP.
                    # (╯°□°)╯︵ ┻━┻
                    if header :contains "X-RSS-Link" "https://it.sentinelone.com" { 
                        addflag "italian";
                    }

                    fileinto :create "Feed.Blog.Sentinelone";
                    stop;
    }

    # rule:[Cloudflare]
    # https://blog.cloudflare.com
    if allof ( header :is "X-RSS-Feed" "https://blog.cloudflare.com/",
               header :contains "Keywords" [ "security", "Vulnerabilit" ] ) {
        fileinto :create "Feed.Blog.Cloudflare";
        stop;
    }

    # rule:[Grsecurity]
    # https://www.grsecurity.net/blog
    if header :is "X-RSS-Feed" "https://www.grsecurity.net/blog.rss" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Intezer]
    # https://www.intezer.com/blog/
    if header :contains "X-RSS-Feed" "https://www.intezer.com" {
        fileinto :create "Feed.Blog.Intezer";
        stop;
    }

    # rule:[Avast]
    # https://decoded.avast.io/
    if header :is "X-RSS-Feed" "https://decoded.avast.io" {
        fileinto :create "Feed.Blog.Avast";
        stop;
    }

    # rule:[Google Project Zero]
    # https://googleprojectzero.blogspot.com/
    if header :contains "X-RSS-Feed" "https://googleprojectzero.blogspot.com" {
        fileinto :create "Feed.Blog.Project Zero";
        stop;
    }

    # rule:[Thunderbird Blog]
    # https://blog.thunderbird.net
    if header :contains "X-RSS-Feed" "https://blog.thunderbird.net" {
        fileinto :create "Feed.Blog.Thunderbird";
        stop;
    }

    # rule:[David Buchanan blog]
    # https://www.da.vidbuchanan.co.uk/blog/
    if header :contains "X-RSS-Feed" "https://www.da.vidbuchanan.co.uk/blog/" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Daniel Stenberg]
    # https://daniel.haxx.se/blog/
    if allof( header :contains "X-RSS-Feed" "https://daniel.haxx.se/blog",
              header :contains "Keywords" "Security") {
        fileinto :create "Feed.Blog.Curl";
        stop;
    }

#   ███████╗███████╗██╗███╗   ██╗███████╗
#   ██╔════╝╚══███╔╝██║████╗  ██║██╔════╝
#   █████╗    ███╔╝ ██║██╔██╗ ██║█████╗  
#   ██╔══╝   ███╔╝  ██║██║╚██╗██║██╔══╝  
#   ███████╗███████╗██║██║ ╚████║███████╗
#   ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝

    # rule:[AppSec]
    # https://github.com/Simpsonpt/AppSecEzine
    if header :is "X-RSS-Feed" "https://github.com/Simpsonpt/AppSecEzine/commits/master" {
        fileinto :create "Feed.Ezine.AppSec";
        stop;
    }

    # rule:[POCorGTFO]
    # POC||GTFO Ezine feed - from the Evan Sultanik website (one of the main mirrors)
    # https://www.sultanik.com/pocorgtfo/
    if allof ( header :is       "X-RSS-Feed" "https://www.sultanik.com/",
               header :contains "X-RSS-Link" "https://www.sultanik.com/pocorgtfo" ) {
        fileinto :create "Feed.Ezine.POCorGTFO";
        stop;
    }

    # rule:[uninformed]
    # http://uninformed.org/
    if header :is "X-RSS-Feed" "http://uninformed.org/" {
        fileinto :create "Feed.Ezine.Uninformed";
        stop;
    }

#   ███████╗███████╗ ██████╗     █████╗ ██████╗ ██╗   ██╗██╗███████╗ ██████╗ ██████╗ ██╗   ██╗
#   ██╔════╝██╔════╝██╔════╝    ██╔══██╗██╔══██╗██║   ██║██║██╔════╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
#   ███████╗█████╗  ██║         ███████║██║  ██║██║   ██║██║███████╗██║   ██║██████╔╝ ╚████╔╝ 
#   ╚════██║██╔══╝  ██║         ██╔══██║██║  ██║╚██╗ ██╔╝██║╚════██║██║   ██║██╔══██╗  ╚██╔╝  
#   ███████║███████╗╚██████╗    ██║  ██║██████╔╝ ╚████╔╝ ██║███████║╚██████╔╝██║  ██║   ██║   
#   ╚══════╝╚══════╝ ╚═════╝    ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   

    # rule:[GitHub Security Advisory]
    # https://securitylab.github.com/
    if header :is "X-RSS-Feed" "https://securitylab.github.com/" {
        fileinto :create "Feed.SA.Github";
        stop;
    }

    # rule:[Drupal]
    # https://www.drupal.org/security
    if header :contains "X-RSS-Feed" "https://www.drupal.org/security" {
        fileinto :create "Feed.SA.Drupal";
        stop;
    }

    # rule:[PowerDNS]
    # https://powerdns.com
    if allof ( header :is "X-RSS-Feed" "https://blog.powerdns.com",
               header :contains "Subject" "Security Advisory" ) {
        fileinto :create "Feed.SA.PowerDNS";
        stop;
    }

    # rule:[RustSec]
    # https://rustsec.org - SA for Rust crates published via crates.io
    if header :is "X-RSS-Feed" "https://rustsec.org/" {
        addflag "rustsec";
        fileinto :create "Feed.SA.Rust";
        stop;
    }

    # rule:[Rust]
    # https://blog.rust-lang.org/ - SA from the main Rust blog
    if allof (  header :is "X-RSS-Feed" "https://blog.rust-lang.org/",
                header :contains "Subject" "Security advisor" ) {
                    addflag "rust-blog";
                    fileinto :create "Feed.SA.Rust";
                    stop;
    }

    # Debian Security Advisories (DSA) are fetched from the debian-security-announce ML, since
    # it provides much more detailed information compared to the DSA RSS-feed.
    # DSA ML:       https://lists.debian.org/debian-security-announce/
    # DSA RSS-feed: https://www.debian.org/security/dsa

    # Ubuntu Security Notice (USN) are fetched from the ubuntu-security-announce ML.
    # USN:          https://lists.ubuntu.com/mailman/listinfo/ubuntu-security-announce

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

    # rule:[Fedora]
    # https://bodhi.fedoraproject.org/updates/?search=&type=security
    if header :is "X-RSS-Feed" "https://bodhi.fedoraproject.org/rss/updates/?search=&status=stable&type=security" {
        fileinto :create "Feed.SA.Distro.Fedora";
        stop;
    }

    # rule:[GCP]
    # https://cloud.google.com/support/bulletins
    if header :contains "X-RSS-Link" "https://cloud.google.com/support/bulletins/index#" {
        fileinto :create "Feed.SA.GCP";
        stop;
    }

    # Jenkins SA are fetched from the osss ML.
    # http://oss-security.openwall.org/wiki/mailing-lists/oss-security

    # Xen SA (XSA) are fetched from the xen-announce ML.
    # https://lists.xenproject.org/cgi-bin/mailman/listinfo/xen-announce

    # Weechat SA are fetched from the weechat-security ML.
    # https://lists.nongnu.org/mailman/listinfo/weechat-security

    # rule:[TOR SA]
    # https://tails.boum.org/security/index.en.html
    if header :contains "X-RSS-Feed" "https://tails.boum.org/security/index.en.html" {
        fileinto :create "Feed.SA.TOR";
        stop;
    }

    # rule:[VLC]
    # https://www.videolan.org/security/
    if allof( header :contains "X-RSS-Feed" "http://www.videolan.org/",
              body :contains [ "security", "affected" ] ) {
        fileinto :create "Feed.SA.VLC";
        stop;
    }

    # rule:[Mozilla]
    # Mozilla SA (Firefox and Thunderbird)
    # https://www.mozilla.org/en-US/security/advisories/
    if header :is "X-RSS-Feed" "https://www.mozilla.org/en-US/security/advisories/" {
        fileinto :create "Feed.SA.Mozilla";
        stop;
    }

    # rule:[OpenWRT]
    # OpenWRT SA
    # https://openwrt.org/advisory/start
    if header :contains "X-RSS-Feed" "https://openwrt.org/advisory" {
        fileinto :create "Feed.SA.OpenWRT";
        stop;
    }

    # OpenJDK Vulnerability Advisory are fetched from the vuln-announce ML.
    # https://mail.openjdk.org/mailman/listinfo/vuln-announce

#   ██████╗ ███████╗██╗     ███████╗ █████╗ ███████╗███████╗
#   ██╔══██╗██╔════╝██║     ██╔════╝██╔══██╗██╔════╝██╔════╝
#   ██████╔╝█████╗  ██║     █████╗  ███████║███████╗█████╗  
#   ██╔══██╗██╔══╝  ██║     ██╔══╝  ██╔══██║╚════██║██╔══╝  
#   ██║  ██║███████╗███████╗███████╗██║  ██║███████║███████╗
#   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝

    # rule:[Chrome]
    # https://chromereleases.googleblog.com
    if allof ( header :contains "X-RSS-Feed" "chromereleases.googleblog.com",
               header :contains "Keywords" "Desktop Update",
               header :contains "Keywords" "Stable updates" ) {
        fileinto :create "Feed.Release.Chrome";
        stop;
    }

    # rule:[ClamAV]
    # https://www.clamav.net/
    if header :is "X-RSS-Feed" "http://blog.clamav.net/" {
        fileinto :create "Feed.Release.ClamAV";
        stop;
    }

    # rule:[Podman]
    # https://www.drupal.org/security
    if header :is "X-RSS-Feed" "https://github.com/containers/podman/releases" {
        fileinto :create "Feed.Release.Podman";
        stop;
    }

    # rule:[SUSE userscripts]
    # https://gitlab.suse.de/gsonnu/userscripts
    if header :is "X-RSS-Feed" "https://gitlab.suse.de/gsonnu/userscripts" {
        fileinto :create "Feed.Release.SUSE Tools";
        stop;
    }

    # rule:[SUSE imtools]
    # https://gitlab.suse.de/security/imtools
    if header :is "X-RSS-Feed" "https://gitlab.suse.de/security/imtools" {
        fileinto :create "Feed.Release.SUSE Tools";
        stop;
    }

    # rule:[SUSE secbox]
    # https://github.com/StayPirate/secbox
    if header :is "X-RSS-Feed" "https://github.com/StayPirate/secbox/releases" {
        fileinto :create "Feed.Release.SUSE Tools";
        stop;
    }

    # Nmap/Npcap announcements are fetched from the nmap announce ML.
    # https://nmap.org/mailman/listinfo/announce

    # rule:[intel ucode]
    # https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files
    if header :is "X-RSS-Feed" "https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases" {
        fileinto :create "Feed.Release.ucode.Intel";
        stop;
    }

    # rule:[KeePassXC]
    # https://github.com/keepassxreboot/keepassxc/releases
    # https://keepassxc.org/blog/
    if header :is "X-RSS-Feed" "https://github.com/keepassxreboot/keepassxc/releases" {
        fileinto :create "Feed.Release.KeePassXC";
        stop;
    }

    # rule:[Unifi Controller]
    # https://community.ui.com/rss/releases/UniFi-Network-Application/e6712595-81bb-4829-8e42-9e2630fabcfe
    if header :is "X-RSS-Feed" "https://community.ui.com" {
        fileinto :create "Feed.Release.Unifi Controller";
        stop;
    }

    # rule:[Apple Products]
    # https://developer.apple.com/news/releases/
    if header :is "X-RSS-Feed" "https://developer.apple.com/news/" {
        # I'm only interested to stable iOS updates
        if allof(     header :contains "Subject" "iOS",
                  not header :contains "Subject" "beta",
                  not header :contains "Subject" "RC" ) {
            fileinto :create "Feed.Release.Apple";
            stop;
        }
    }

    # rule:[foot]
    # https://codeberg.org/dnkl/foot/releases
    if header :is "X-RSS-Feed" "https://codeberg.org/dnkl/foot/releases" {
        fileinto :create "Feed.Release.Foot";
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

    # CyberSaiyan (ITA)
    # https://cybersaiyan.us17.list-manage.com

#   ███╗   ██╗███████╗██╗    ██╗███████╗
#   ████╗  ██║██╔════╝██║    ██║██╔════╝
#   ██╔██╗ ██║█████╗  ██║ █╗ ██║███████╗
#   ██║╚██╗██║██╔══╝  ██║███╗██║╚════██║
#   ██║ ╚████║███████╗╚███╔███╔╝███████║
#   ╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝ ╚══════╝

    # rule:[Archlinux News]
    # https://archlinux.org/news/
    # It handles the same content of arch-announce ML
    if header :is "X-RSS-Feed" "https://archlinux.org/news/" {
        fileinto :create "Feed.News.Archlinux";
        stop;
    }

    # rule:[web3isgoinggreat]
    # https://web3isgoinggreat.com/
    # Scams in the cryptocurrency world
    if header :is "X-RSS-Feed" "https://web3isgoinggreat.com" {
        fileinto :create "Feed.News.Crypto Scam";
        stop;
    }

    # rule:[breaches from HIBP]
    # https://haveibeenpwned.com/
    # Scams in the cryptocurrency world
    if header :is "X-RSS-Feed" "https://haveibeenpwned.com" {
        fileinto :create "Feed.News.Breaches";
        stop;
    }

#   ██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
#   ██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
#   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
#   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
#   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
#    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

    # rule:[SAMSH MRs to master]
    # https://gitlab.suse.de/tools/smash/-/merge_requests?scope=all&state=merged&target_branch=master
    if header :is "X-RSS-Feed" "https://gitlab.suse.de/tools/smash/-/merge_requests" {

        redirect "${WORK_ADDR}";
        discard;
        stop;
    }

#   ██████╗  ██████╗ ██████╗  ██████╗ █████╗ ███████╗████████╗
#   ██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝
#   ██████╔╝██║   ██║██║  ██║██║     ███████║███████╗   ██║   
#   ██╔═══╝ ██║   ██║██║  ██║██║     ██╔══██║╚════██║   ██║   
#   ██║     ╚██████╔╝██████╔╝╚██████╗██║  ██║███████║   ██║   
#   ╚═╝      ╚═════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   

    # rule:[Late Night Linux]
    # Late Night Linux, Linux Downtime, and Linux After Dark
    # https://latenightlinux.com
    if header :contains "X-RSS-Feed" "https://latenightlinux.com" {
        fileinto :create "Feed.Podcast.Late Night Linux";
        stop;
    }

    # rule:[Ubuntu security podcast]
    # https://ubuntusecuritypodcast.org
    if header :is "X-RSS-Feed" "https://ubuntusecuritypodcast.org/" {
        fileinto :create "Feed.Podcast.Ubuntu Security";
        stop;
    }

    # rule:[Dayzerosec Podcast]
    # https://dayzerosec.com/podcast/
    if header :is "X-RSS-Feed" "https://dayzerosec.com/" {
        fileinto :create "Feed.Podcast.Dayzerosec";
        stop;
    }

    # rule:[Darknet Diaries Podcast]
    # https://darknetdiaries.com/
    if header :is "X-RSS-Feed" "https://open.spotify.com/show/4XPl3uEEL9hvqMkoZrzbx5" {
        fileinto :create "Feed.Podcast.Darknet Diaries";
        stop;
    }

    # rule:[Thundebird Podacast]
    # https://blog.thunderbird.net/2023/03/thundercast-1-origin-stories/
    if header :is "X-RSS-Feed" "https://thunderbird.net" {
        fileinto :create "Feed.Podcast.Thundebird";
        stop;
    }

    # rule:[Fossified]
    # https://pod.fossified.com/
    # https://github.com/fossified/podcast
    if header :contains "X-RSS-Feed" "https://pod.fossified.com" {
        fileinto :create "Feed.Podcast.Fossified";
        stop;
    }

    # rule:[Open Source Security Podcast]
    # https://opensourcesecurity.io/
    if header :is "X-RSS-Feed" "http://opensourcesecuritypodcast.com" {
        fileinto :create "Feed.Podcast.Open Source Security";
        stop;
    }

#    ██████╗ ████████╗██╗  ██╗███████╗██████╗ 
#   ██╔═══██╗╚══██╔══╝██║  ██║██╔════╝██╔══██╗
#   ██║   ██║   ██║   ███████║█████╗  ██████╔╝
#   ██║   ██║   ██║   ██╔══██║██╔══╝  ██╔══██╗
#   ╚██████╔╝   ██║   ██║  ██║███████╗██║  ██║
#    ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

    #_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#
    #                                                                       #
    #   If the notification hasn't matched any rule then move it to Trash   #
    #                                                                       #
    #_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#

    #discard;
    fileinto :create "Trash";

}