# echo

Category: files

Summary: Print text, or write/append it to a file

Usage:

```
echo <text> [> path | >> path]
```

Manual:

```
DESCRIPTION
    Prints text, or writes it to a file on the SD card: '>' replaces
    the file, '>>' appends to it. Each write ends with a newline. Put
    spaces around '>'/'>>'; use quotes to keep extra spaces.

EXAMPLES
    root@espjack# echo hello world
    hello world

    root@espjack# echo administrator > /wordlists/users.txt
    Wrote /wordlists/users.txt

    root@espjack# echo jsmith >> /wordlists/users.txt
    Appended to /wordlists/users.txt
```
