# Personal sieve scripts collection

This repository is intended to store and organize my personal sieve scripts. Since their complexity grows every day I decided to organize them in a better way: split them into multiple files while versioning via git. Using the below-described [git-hook](#The-git-way), at each git commit the scripts are automatically uploaded to the mail-server.

## Requirement
You need `sieveshell` installed. Good news for [secbox](https://github.com/StayPirate/secbox) users, in case you are running `secbox >= 1.10` and `secbox-image >= 2.7`, then you already have `sieveshell` available. You can double-check with the following commands:
```bash
> secbox -v
script     :  secbox                                                       v.1.9
image      :  non_public/maintenance/security/container/containers/secbox  v.2.7
container  :  secbox                                                       running
> which sieveshell
sieveshell: aliased to secbox --no-tty sieveshell
```

## How to use

1. ### **The manual way**

    I store my credentials (application password) in a local keyring. I can access them from D-Bus via `org.freedesktop.secrets`. The following functions are intended to collect all the needed information from the local secret service provider (keepassxc in my case).

    ```bash
    get_user() {
        secret-tool search account ${account} 2>&1 | \
        grep -E "^attribute\.UserName" | \
        cut -d " " -f3
    }
    
    get_pass() {
        secret-tool search account ${account} 2>&1 | \
        grep -E "^secret" | \
        cut -d " " -f3
    }
    
    get_managesieve_port() {
        secret-tool search account ${account} 2>&1 | \
        grep -E "^attribute\.managesieve_port" | \
        cut -d " " -f3
    }
    
    get_managesieve_addr() {
        secret-tool search account ${account} 2>&1 | \
        grep -E "^attribute\.managesieve_addr" | \
        cut -d " " -f3
    }
    ```

    From inside the repo work-tree, I run the following command to upload the *.sieve scripts to the mail-server. This can be hooked to git in a way that it automatically updates the sieve scripts at every new commit (see below).

    ```bash
    find $(git rev-parse --show-toplevel) -type f -name "*.sieve" -printf "put %p %f\n" | sort -nr | \
    sieveshell --user $(get_user) \
            --passwd $(get_pass) \
            --use-tls \
            --port $(get_managesieve_port) \
            $(get_managesieve_addr)
    ```

2. ### **The git way**

    The [hook](.githooks/pre-commit) is already provided within this repository, I strongly suggest you leverage [conditional includes](https://git-scm.com/docs/git-config#_conditional_includes) (cool beans) in your gitconfig. This will be as easy as appending the following lines to your `~/.gitconfig` (e.g. [mine](https://github.com/StayPirate/dotfiles/blob/ebb1fdd4eba76b7a5bae77d512ec3ba7f0d16549/.gitconfig#L29-L31)):

    ```
    ; Only include if the repository is sieve-susede
    [includeIf "gitdir:~/Workspace/sieve-susede/.git"]
            path = ~/Workspace/sieve-susede/.githooks/sieveshell.gitconfig
    ```
    <sup>\* Do not forget to adjust the paths in the above snippet.</sup> 
    
    You can now jump into your local repository copy, make your changes and commit.

---
At each run of the pre-commit hook a check occurs to ensure that `00-Init.sieve` is active, if not it will be activated.