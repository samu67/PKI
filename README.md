# ASL Project

## Components
Our submission comprises six virtual machines:
- The firewall: `fw.ova`
- The database server: `db.ova`
- The backup server: `bkp.ova`
- the CA server: `ca.ova`
- The webserver: `www.ova`
- the client machine: `client.ova`

## Installation
In order to install the virtual machines, you need to 
1. import all the `.ova` files in VirtualBox and 
1. choosing *Include all network adapter MAC address*. 

The network interfaces should be setup properly but in case it is not here are network interfaces which should be made available to the VMs:
- `fw`: 
    - Adapter 1: Internal Network: '*core*'
    - Adapter 2: Internal Network: '*dmz*'
    - Adapter 3: NAT
    - Adapter 4: Internal Network: '*clientside*'
- `db`:
    - Adapter 1: Internal Network: '*core*'
- `bkp`:
    - Adapter 1: Internal Network: '*core*'
- `ca`:
    - Adapter 1: Internal Network: '*core*'
- `www`:
    - Adapter 1: Internal Network: '*dmz*'
- `client`
    - Adapter 1: NAT
    - Adapter 1: Internal Network: '*clientside*'

## Black-box analysis credentials:
The client machine is configured with a regular user account `usr` whose password is "`qwertyuiop`" and the root user's password is also "`qwertyuiop`". 

### Client & CA admin interface
Using the client vm, you should be able to navigate to the client web interface by simply navigating to `www.imovies.com` using Firefox. The certificate for Firefox to recognize `www.imovies.com` as legitimate is already installed in Firefox but is also available in the home directory as `CACert.pem`. A user certificate is also available to login as a regular user (`cert-user.p12`) and another one is available to log in with a user which is CA admin to access the CA administration panel (`cert-ca-admin.p12`). In order to install them you need to go in the Firefox preferences > Privacy & security > Certificates > View Certificates > Your certificates > import... On import, you will be prompted for the keyfile password which is "`A`".

The usernames and passwords of registered users are listed below:

| username | password    |
|----------|-------------|
| lb       | D15Licz6    |
| ps       | KramBamBuli |
| ms       | MidbSvlJ    |
| a3       | Astrid      |

For easier access to the system, we provide NAT port forwarding on the NAT interface of the firewall. Using this, it is possible to access the following resources using the following aliases:

- `fw`:
    - port 22: `127.0.0.1:2201`
- `db`:  
    - port 22: `127.0.0.1:2202`
- `bkp`:  
    - port 22: `127.0.0.1:2203`
- `ca`:
    - port 22: `127.0.0.1:2204`
- `www`:
    - port 22: `127.0.0.1:2221`
    - port 80: `127.0.0.1:8080`
    - port 443: `127.0.0.1:4443`

In order for the port forwarding to work please make sure the NAT network interface of the firewall (`fw.ova`) has a port forwarding table filled as follows: 

| Name    | Protocol | Host IP   | Host port | Guest IP  | Guest port |
|---------|----------|-----------|-----------|-----------|------------|
| http    | TCP      | 127.0.0.1 | 8080      | 10.0.4.15 | 80         |
| https   | TCP      | 127.0.0.1 | 4443      | 10.0.4.15 | 443        |
| ssh bkp | TCP      | 127.0.0.1 | 2203      | 10.0.4.15 | 2203       |
| ssh ca  | TCP      | 127.0.0.1 | 2204      | 10.0.4.15 | 2204       |
| ssh db  | TCP      | 127.0.0.1 | 2202      | 10.0.4.15 | 2202       |
| ssh fw  | TCP      | 127.0.0.1 | 2201      | 10.0.4.15 | 22         |
| ssh www | TCP      | 127.0.0.1 | 2212      | 10.0.4.15 | 2212       |

## White-box analysis information
### Credentials

The system administration connection is provided using an ssh key-pair whose private key is below:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCwTZg+W6
CyTnx6I9HOYzihAAABAAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIOTgkWBGD0EVHTKO
5CXvfA9aWj+7PJmax15emL+Q1HEIAAAAkNv3Ui+3WYc/LVzXYciUoL0hJibV4xQg+e3xxj
B3gzRljrp9kUiWZJiCVxvNf4V/9K48lhYIUm6mB3Por69yNr7X4XSiBXMCJAjcT8EZqJ+r
zJ/NIhZSVuKhYrXH5SMv9d6CBZuP6xvDEbZmszTh+3o/KXXk/pzl0pCLzIWpvpl1v0dGHf
1NCiov1JaPbUVZbA==
-----END OPENSSH PRIVATE KEY-----
```
The password needed to use the key is:
```
7h3eD9Zjj.G!!q8zX3ek4Nq*ifXRGX8R4Yh!HrMRJLvAJdvrW2m_fGX2tVfFU9
``` 
The login is only permitted to the unprivileged user `usr`. In order to escalate to the user `root`, it is necessary to provide the root password. The `usr` and `root` passwords are listed below:

- `fw`: 
    - `usr`: "`POPULAR-ford-newsboy-awhirl`"
    - `root`: "`dolor-claret-SKEET-sterling`"
- `db`:  
    - `usr`: "`pidgin-STRIAE-true-daddy`"
    - `root`: "`waddle-guess-HEATHER-salmon`"
- `bkp`:  
    - `usr`: "`cyclic-SUBLIME-rapine-bombast`"
    - `root`: "`signpost-brocade-javelin-GIRL`"
- `ca`:  
    - `usr`: "`password123`"
    - `root`: "`password123`"
- `www`:  
    - `usr`: "`cajole-pend-REVERT-nice`"
    - `root`: "`frogman-ASEXUAL-syrinx-despatch`"

### Configuration & program files
The configuration files of nginx, nftables, rsyslog, and networking are at their default location (`/etc/nftables.conf`, `/etc/nginx/...`, `/etc/rsyslog.d/...`, `/etc/hosts`, `/etc/network/interfaces`, ...). On the database, ca, and webserver the flask app files are stored in `/home/usr/app/` and the pki files used by nginx are in `/root/nginx/...`. On the database, ca, webserver, and firewall, the backup scripts are in `/root/backup/...`. On the database, ca, webserver, and firewall, the pki files used by rsyslog are in `/root/rsyslog/...`.
