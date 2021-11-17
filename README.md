# ASL confgen

These scripts generate the configuration files for the VMs of the ASL project.

# Disclaimer:
When generating configuration files, the script deletes the content of subfolders whose names are the same as the hostnames for which the configuration files are being generated.
Moreover, the input of `confgen` is sanitized a bit, but be careful what you put there since this piece of code is in the script:

```bash
rm -rf "$hname/*";
```
(and yes, `$hname` is the argument to the script oopsie)

Also, it might be possible the names of the interfaces I had on my VMs are different from yours so if networking doesn't work, please check in `/etc/network/interfaces` and `/etc/nftables.conf` that the correct interface names show up.

## `confgen`: 
To generate the configuration files of a machine with hostname `HOSTNAME`:

```bash
$ ./confgen -h HOSTNAME
```

The script generates the following configuration files and puts them in a new subfolder called `HOSTNAME`.
The possible values for the hostnames are: `fw`, `www`, `ca`, `db`, and `bkp`.

## `allconfsgen`:
This script iterates through the possible hostnames and for each hostname generates the configuration files:

```bash
$ ./allconfsgen
```
