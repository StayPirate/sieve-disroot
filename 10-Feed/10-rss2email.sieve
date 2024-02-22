require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include", "imap4flags", "body", "regex" ];

global [ "WORK_ADDR", "RSS2EMAIL" ];

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

#   ██████╗ ██╗      ██████╗  ██████╗ 
#   ██╔══██╗██║     ██╔═══██╗██╔════╝ 
#   ██████╔╝██║     ██║   ██║██║  ███╗
#   ██╔══██╗██║     ██║   ██║██║   ██║
#   ██████╔╝███████╗╚██████╔╝╚██████╔╝
#   ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ 

    # rule:[Chromium Blog (security)]
    # http://blog.chromium.org
    if allof ( header :contains "X-RSS-Feed" "blog.chromium.org",
               header :contains "Keywords" [ "security", "HTTPS" ] ) {
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
    if allof ( header :is "X-RSS-Feed" "https://blog.torproject.org/",
               not header :contains "Subject" "New",
               not header :contains "Subject" "Release:" ) {
        fileinto :create "Feed.Blog.TOR";
        stop;
    }

    # rule:[Guerre di rete]
    # https://guerredirete.substack.com
    if header :is "X-RSS-Feed" "https://guerredirete.substack.com" {
        addflag "italian";
        fileinto :create "Feed.Blog.Guerredirete";
        stop;
    }

    # rule:[MiaMammaUsaLinux]
    # https://www.miamammausalinux.org
    if header :is "X-RSS-Feed" "https://www.miamammausalinux.org" {
        addflag "italian";
        fileinto :create "Feed.Blog.MiaMammaUsaLinux";
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

    # rule:[Hermes Press]
    # Center for Transparency and Digital Human Rights
    # https://www.hermescenter.org/press/
    if header :is "X-RSS-Feed" "https://www.hermescenter.org" {
        fileinto :create "Feed.Blog.Hacktivism";
        addflag "italian";
        stop;
    }

    # rule:[copernicani]
    # https://www.copernicani.it
    if allof ( header :is "X-RSS-Feed" "https://www.copernicani.it",
               header :contains "Keywords" [ "cybersecurity", "cyberwarfare" ] ) {
        fileinto :create "Feed.Blog.Hacktivism";
        addflag "italian";
        stop;
    }

    # rule:[Sentinelone]
    # https://sentinelone.com/blog/
    if allof ( header :contains "X-RSS-Feed" "sentinelone.com",
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
    if header :contains "X-RSS-Feed" "intezer.com" {
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

    # rule:[Sekoia Blog]
    # https://blog.sekoia.io/
    if allof( header :contains "X-RSS-Feed" "https://blog.sekoia.io",
              header :contains "Keywords" [ "Security", "Cybercrime", "Dark Web", "APT", "Malware", "CTI" ]) {
        fileinto :create "Feed.Blog.Sekoia";
        stop;
    }

    # rule:[Kaspersky Securelist]
    # https://securelist.com/
    if allof( header :contains "X-RSS-Feed" "https://securelist.com",
              header :contains "Keywords" [ "Malware", "Incidents", "Research" ]) {
        fileinto :create "Feed.Blog.Securelist";
        stop;
    }

    # rule:[Uptycs]
    # https://www.uptycs.com/blog
    if allof( header :contains "X-RSS-Feed" "https://www.uptycs.com",
              header :contains "Keywords" [ "Malware", "supply chain" ]) {
        fileinto :create "Feed.Blog.Uptycs";
        stop;
    }

    # rule:[Citizen Lab]
    # https://citizenlab.ca/category/research/
    if header :contains "X-RSS-Feed" "https://citizenlab.ca" {
        fileinto :create "Feed.Blog.Citizen Lab";
        stop;
    }

    # rule:[Gankra]
    # https://faultlore.com/blah/#articles
    if header :contains "X-RSS-Feed" "https://gankra.github.io/blah/" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Mandiant]
    # https://www.mandiant.com/resources/blog
    if header :contains "X-RSS-Feed" "https://www.mandiant.com" {
        fileinto :create "Feed.Blog.Mandiant";
        stop;
    }

    # rule:[Matthew Garrett]
    # https://mjg59.dreamwidth.org/
    if header :contains "X-RSS-Feed" "https://mjg59.dreamwidth.org/" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Scott Helme]
    # https://scotthelme.co.uk/
    # Ignore any blog post related to his product "Report URI"
    if allof ( header :contains "X-RSS-Feed" "https://scotthelme.co.uk/",
               not header :is "Keywords" "Report URI",
               not header :contains "Subject" "Report URI" ) {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Martijn Braam]
    # https://blog.brixit.nl
    if header :contains "X-RSS-Feed" "https://blog.brixit.nl" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Memorysafety]
    # https://www.memorysafety.org
    if header :contains "X-RSS-Feed" "https://www.memorysafety.org" {
        fileinto :create "Feed.Blog.Memorysafety";
        stop;
    }

    # rule:[Elastic - Security Labs]
    # https://www.elastic.co/security-labs/
    if header :contains "X-RSS-Feed" "https://www.elastic.co/security-labs" {
        fileinto :create "Feed.Blog.ELK Security Labs";
        stop;
    }

    # rule:[Aqua Security]
    # https://blog.aquasec.com
    if allof( header :contains "X-RSS-Feed" "https://blog.aquasec.com",
              not header :regex "Keywords" [ ".*aqua.*", ".*Aqua.*" ],
              not header :contains "Subject" "aqua" ) {
        fileinto :create "Feed.Blog.Aquasec";
        stop;
    }

    # rule:[Symantec Security]
    # https://symantec-enterprise-blogs.security.com/blogs/
    if header :contains "X-RSS-Feed" "https://sed-cms.broadcom.com" {
        fileinto :create "Feed.Blog.Symantec";
        stop;
    }

    # rule:[Jared Candelaria]
    # https://calabi-yau.space/blog/
    if header :contains "X-RSS-Feed" "https://calabi-yau.space" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Axel -0vercl0k- Souchet]
    # https://doar-e.github.io
    if header :contains "X-RSS-Feed" "https://doar-e.github.io" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Adam Zabrocki]
    # http://blog.pi3.com.pl
    if header :contains "X-RSS-Feed" "http://blog.pi3.com.pl" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Thalium]
    # https://blog.thalium.re/
    if header :contains "X-RSS-Feed" "https://blog.thalium.re" {
        fileinto :create "Feed.Blog.Thalium";
        stop;
    }

    # rule:[James Forshaw]
    # James (tiraniddo) Forshaw - Google Project Zero
    # https://www.tiraniddo.dev/
    if header :contains "X-RSS-Feed" "https://www.tiraniddo.dev" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Moshe -0xkol- Kol]
    # https://0xkol.github.io/
    if header :contains "X-RSS-Feed" "https://0xkol.github.io" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[JPCERT Coordination Center official Blog]
    # https://blogs.jpcert.or.jp/en/
    if header :contains "X-RSS-Feed" "https://blogs.jpcert.or.jp/en" {
        fileinto :create "Feed.Blog.jpcert";
        stop;
    }

    # rule:[ESET]
    # https://www.welivesecurity.com/research/
    if header :contains "X-RSS-Feed" "https://www.welivesecurity.com" {
        fileinto :create "Feed.Blog.eset";
        stop;
    }

    # rule:[ZDI Blog]
    # https://www.zerodayinitiative.com/blog
    if header :contains "X-RSS-Feed" "thezdi.com/blog" {
        fileinto :create "Feed.Blog.ZDI";
        stop;
    }

    # AhnLab Security Emergency Response Center (ASEC)
    # https://asec.ahnlab.com/en/
    if header :contains "X-RSS-Feed" "asec.ahnlab.com" {
        fileinto :create "Feed.Blog.ASEC";
        stop;
    }

    # KPXC Blog
    # https://keepassxc.org/blog/
    if header :contains "X-RSS-Feed" "keepassxc.org/blog" {
        fileinto :create "Feed.Blog.KeePassXC";
        stop;
    }

    # Wiz Blog
    # https://www.wiz.io/blog
    if allof ( header :contains "X-RSS-Feed" "wiz.io",
               not header :contains "Subject" [ "Wiz", "wiz" ] ) {
        fileinto :create "Feed.Blog.Wiz";
        stop;
    }

    # Isosceles Blog
    # https://blog.isosceles.com/
    if header :contains "X-RSS-Feed" "isosceles.com" {
        fileinto :create "Feed.Blog.Isosceles";
        stop;
    }

    # Gitlab Blog
    # https://about.gitlab.com/blog/categories/security/
    if allof ( header :contains "X-RSS-Feed" "gitlab.com/blog",
               not header :contains "Subject" "Security Release",
               anyof ( header :contains "Subject" [ "Security", "security" ],
                       body :contains [ "Security", "security" ] )) {
        fileinto :create "Feed.Blog.Gitlab";
        stop;
    }

    # rule:[Binarly Blog]
    # https://binarly.io/posts/index.html
    if header :contains "X-RSS-Feed" "binarly.io/posts" {
        fileinto :create "Feed.Blog.Binarly";
        stop;
    }

    # rule:[FIRST Blog]
    # https://www.first.org/blog/
    if header :contains "X-RSS-Feed" "first.org/blog" {
        fileinto :create "Feed.Blog.FIRST";
        stop;
    }

    # rule:[Steve on Security Blog]
    # https://syfuhs.net/
    if header :contains "X-RSS-Feed" "syfuhs.net" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[Maksim Chudakov Blog]
    # https://www.chudamax.com/
    if header :contains "X-RSS-Feed" "chudamax.com" {
        fileinto :create "Feed.Blog.Good Reads";
        stop;
    }

    # rule:[The Hacker's Choice (THC) Blog and KB]
    # https://blog.thc.org/
    if header :contains "X-RSS-Feed" [ "blog.thc.org", "iq.thc.org" ] {
        fileinto :create "Feed.Blog.THC";
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
    if allof ( header :is "X-RSS-Feed" "https://blog.rust-lang.org/",
               header :contains "Subject" "Security advisor" ) {
        addflag "rust-blog";
        fileinto :create "Feed.SA.Rust";
        stop;
    }

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

    # rule:[Gitlab Security Releases]
    # https://about.gitlab.com/releases/categories/releases/
    if header :contains "X-RSS-Feed" "https://about.gitlab.com/releases/categories/releases/" {
        fileinto :create "Feed.SA.Gitlab";
        stop;
    }

    # rule:[ZDI Upcoming SA]
    # https://www.zerodayinitiative.com/advisories/upcoming/
    if header :contains "X-RSS-Feed" "zerodayinitiative.com/advisories/upcoming" {
        fileinto :create "Feed.SA.ZDI.Upcoming";
        stop;
    }

    # rule:[ZDI Published SA]
    # https://www.zerodayinitiative.com/advisories/published/
    if header :contains "X-RSS-Feed" "zerodayinitiative.com/advisories/published" {
        fileinto :create "Feed.SA.ZDI.Published";
        stop;
    }

    # rule:[Binarly SA]
    # https://binarly.io/advisories/index.html
    if header :contains "X-RSS-Feed" "binarly.io/advisories" {
        fileinto :create "Feed.SA.Binarly";
        stop;
    }

    # rule:[Linux Kernel CNA SA]
    # https://lore.kernel.org/linux-cve-announce/
    if header :contains "X-RSS-Feed" "lore.kernel.org/linux-cve-announce/" {
        fileinto :create "Feed.SA.Linux";
        stop;
    }

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
               header :contains "Keywords" "Stable updates",
               body :contains [ "linux", "Linux" ] ) {
        fileinto :create "Feed.Release.Chrome";
        stop;
    }

    # rule:[ClamAV]
    # https://www.clamav.net/
    if header :is "X-RSS-Feed" "http://blog.clamav.net/" {
        fileinto :create "Feed.Release.ClamAV";
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

    # rule:[SUSE secbox-image]
    # https://gitlab.suse.de/security/secbox-image
    if header :is "X-RSS-Feed" "https://gitlab.suse.de/security/secbox-image" {
        fileinto :create "Feed.Release.SUSE Tools";
        stop;
    }

    # rule:[SUSE secbox]
    # https://github.com/StayPirate/secbox
    if header :is "X-RSS-Feed" "https://github.com/StayPirate/secbox/releases" {
        fileinto :create "Feed.Release.SUSE Tools";
        stop;
    }

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
        # I'm only interested to stable iOS and watchOS updates
        if allof( header :contains "Subject" [ "iOS", "watchOS" ],
                  not header :contains "Subject" [ "beta", "RC", "Release Candidate" ] ) {
            fileinto :create "Feed.Release.Apple";
            stop;
        }
    }

    # rule:[foot]
    # https://codeberg.org/dnkl/foot/releases
    if header :contains "X-RSS-Feed" "dnkl/foot/release" {
        fileinto :create "Feed.Release.Foot";
        stop;
    }

    # rule:[Wireshark]
    # https://www.wireshark.org/docs/relnotes
    # https://gitlab.com/wireshark/wireshark/-/tags
    if allof( header :contains "X-RSS-Feed" "https://gitlab.com/wireshark/wireshark",
              header :contains "Subject" "wireshark-",
              not header :contains "Subject" "rc" ) {
        fileinto :create "Feed.Release.Wireshark";
        stop;
    }

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

    # rule:[Linuxiac]
    # https://linuxiac.com/
    # Linuxiac is an independent media platform dedicated to publishing the latest news from the Linux
    # world and Open Source software.
    if header :contains "X-RSS-Feed" "https://linuxiac.com" {
        fileinto :create "Feed.News.FOSS";
        stop;
    }

    # rule:[devops.com]
    # https://devops.com/
    if allof( header :contains "X-RSS-Feed" "https://devops.com",
              header :contains "Keywords" [ "security", "sbom", "supply chain", "git", "linux", "2fa", "authentication", "mfa" ] ) {
        fileinto :create "Feed.News.FOSS";
        stop;
    }

    # rule:[Devclass]
    # https://devclass.com - Filter only security related posts
    if allof( header :contains "X-RSS-Feed" "https://devclass.com",
              header :contains "Keywords" "security" ) {
        fileinto :create "Feed.News.Devclass";
        stop;
    }

    # rule:[Phoronix]
    # https://www.phoronix.com
    if header :contains "X-RSS-Feed" "https://www.phoronix.com" {
        fileinto :create "Feed.News.Phoronix";
        stop;
    }

#   ██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
#   ██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
#   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
#   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
#   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
#    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

    # Notify if a MR is merged to the master branch in the SMASH project
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

    # rule:[Mandiant - The Defender's Advantage Podcast]
    # https://www.mandiant.com/resources/blog/podcast-threats-europe
    if header :is "X-RSS-Feed" "https://open.spotify.com/show/7CFsvR9lOLZiNoVDUltL9X" {
        fileinto :create "Feed.Podcast.Mandiant";
        stop;
    }

    # rule:[Naked Security from Sophos]
    # https://nakedsecurity.sophos.com/podcast/
    if header :is "X-RSS-Feed" "https://open.spotify.com/show/4AhwI3oHRgqO4v4Q5ZGaq9" {
        fileinto :create "Feed.Podcast.Naked Security";
        stop;
    }

    # rule:[Security Now]
    # https://twit.tv/shows/security-now
    if header :is "X-RSS-Feed" "https://twit.tv/shows/security-now" {
        fileinto :create "Feed.Podcast.Security Now";
        stop;
    }

    # rule:[the ReadME Podcast]
    # https://github.com/readme
    if anyof( header :contains "X-RSS-Feed" "github.com/readme",
              header :is "X-RSS-Feed" "https://open.spotify.com/show/660KitvdJDX2vUmioAbwSQ" ) {
        fileinto :create "Feed.Podcast.ReadME";
        stop;
    }

    # rule:[The Cyber Show]
    # https://cybershow.uk/
    if header :is "X-RSS-Feed" "https://open.spotify.com/show/0av5zTSOSIuBBtOjqjJWFc" {
        fileinto :create "Feed.Podcast.The Cyber Show";
        stop;
    }

    # rule:[FIRST Impressions]
    # https://www.first.org/podcasts
    if header :is "X-RSS-Feed" "https://open.spotify.com/show/6mdVBCDxhGKuULeca9psdl" {
        fileinto :create "Feed.Podcast.FIRST Impressions";
        stop;
    }

    # rule:[RSS-Bridge errors]
    if allof ( header :contains "X-RSS-Link" "rss-bridge.home",
               header :contains "Subject" "error" ) {
        # A RSS bridge returned a HTTP error. Do not trash, instead send it to INBOX.
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
    addflag "${RSS2EMAIL}";
    fileinto :create "Trash";
    stop;

}