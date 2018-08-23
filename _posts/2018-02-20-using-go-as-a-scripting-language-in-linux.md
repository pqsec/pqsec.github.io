---
layout: post
title: "Using Go as a scripting language in Linux"
description: February 20th, 2018
excerpt: "Why use Go as a scripting language? Short answer: why not? Go is relatively easy to learn, not too verbose and there is a huge ecosystem of libraries which can be reused to avoid writing all the code from scratch."
---

# Using Go as a scripting language in Linux

*This is a repost of my post from [Cloudflare Blog](https://blog.cloudflare.com/using-go-as-a-scripting-language-in-linux/)*

At Cloudflare we like Go. We use it in many [in-house software projects](https://blog.cloudflare.com/what-weve-been-doing-with-go/) as well as parts of [bigger pipeline systems](https://blog.cloudflare.com/meet-gatebot-a-bot-that-allows-us-to-sleep/). But can we take Go to the next level and use it as a scripting language for our favourite operating system, Linux?
![gopher and tux](https://blog.cloudflare.com/content/images/2018/02/gopher-tux-1.png)
<small>[gopher image](https://golang.org/doc/gopher/gophercolor.png) [CC BY 3.0](https://creativecommons.org/licenses/by/3.0/) [Renee French](http://reneefrench.blogspot.com/)</small>
<small>[Tux image](https://pixabay.com/en/linux-penguin-tux-2025536/) [CC0 BY](https://creativecommons.org/publicdomain/zero/1.0/deed.en) [OpenClipart-Vectors](https://pixabay.com/en/users/OpenClipart-Vectors-30363/)</small>
### Why consider Go as a scripting language
Short answer: why not? Go is relatively easy to learn, not too verbose and there is a huge ecosystem of libraries which can be reused to avoid writing all the code from scratch. Some other potential advantages it might bring:

* Go-based build system for your Go project: `go build` command is mostly suitable for small, self-contained projects. More complex projects usually adopt some build system/set of scripts. Why not have these scripts written in Go then as well?
* Easy non-privileged package management out of the box: if you want to use a third-party library in your script, you can simply `go get` it. And because the code will be installed in your `GOPATH`, getting a third-party library does not require administrative privileges on the system (unlike some other scripting languages). This is especially useful in large corporate environments.
* Quick code prototyping on early project stages: when you're writing the first iteration of the code, it usually takes a lot of edits even to make it compile and you have to waste a lot of keystrokes on *"edit->build->check"* cycle. Instead you can skip the "build" part and just immediately execute your source file.
* Strongly-typed scripting language: if you make a small typo somewhere in the middle of the script, most scripts will execute everything up to that point and fail on the typo itself. This might leave your system in an inconsistent state. With strongly-typed languages many typos can be caught at compile time, so the buggy script will not run in the first place.

### Current state of Go scripting
At first glance Go scripts seem easy to implement with Unix support of [shebang lines][shebang] for scripts. A shebang line is the first line of the script, which starts with `#!` and specifies the script interpreter to be used to execute the script (for example, `#!/bin/bash` or `#!/usr/bin/env python`), so the system knows exactly how to execute the script regardless of the programming language used. And Go already supports interpreter-like invocation for `.go` files with `go run` command, so it should be just a matter of adding a proper shebang line, something like `#!/usr/bin/env go run`, to any `.go` file, setting the executable bit and we're good to go.

However, there are problems around using `go run` directly. [This great post][go-scripts-github] describes in detail all the issues around `go run` and potential workarounds, but the gist is:

* `go run` does not properly return the script error code back to the operating system and this is important for scripts, because error codes are one of the most common ways multiple scripts interact with each other and the operating system environment.
* you can't have a shebang line in a valid `.go` file, because Go does not know how to process lines starting with `#`. Other scripting languages do not have this problem, because for most of them `#` is a way to specify comments, so the final interpreter just ignores the shebang line, but Go comments start with `//` and `go run` on invocation will just produce an error like:

```
package main:
helloscript.go:1:1: illegal character U+0023 '#'
```

[The post][go-scripts-github] describes several workarounds for above issues including using a custom wrapper program  [gorun][gorun] as an interpreter, but all of them do not provide an ideal solution. You either:
* have to use non-standard shebang line, which starts with `//`. This is technically not even a shebang line, but the way how `bash` shell processes executable text files, so this solution is `bash` specific. Also, because of the specific behaviour of `go run`, this line is rather complex and not obvious (see [original post][go-scripts-github] for examples).
* have to use a custom wrapper program [gorun][gorun] in the shebang line, which works well, however, you end up with `.go` files, which are not compilable with standard `go build` command because of the illegal `#` character.

### How Linux executes files
OK, it seems the shebang approach does not provide us with an all-rounder solution. Is there anything else we could use? Let's take a closer look how Linux kernel executes binaries in the first place. When you try to execute a binary/script (or any file for that matter which has executable bit set), your shell in the end will just use Linux `execve` [system call](https://en.wikipedia.org/wiki/System_call) passing it the filesystem path of the binary in question, command line parameters and currently defined environment variables. Then the kernel is responsible for correct parsing of the file and creating a new process with the code from the file. Most of us know that Linux (and many other Unix-like operating systems) use [ELF binary format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) for its executables.

However, one of the core principles of Linux kernel development is to avoid "vendor/format lock-in" for any subsystem, which is part of the kernel. Therefore, Linux implements a "pluggable" system, which allows any binary format to be supported by the kernel - all you have to do is to write a correct module, which can parse the format of your choosing. And if you take a closer look at the kernel source code, you'll see that Linux supports more binary formats out of the box. For example, for the recent `4.14` Linux kernel [we can see](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs?h=linux-4.14.y) that it supports at least 7 binary formats (in-tree modules for various binary formats usually have `binfmt_` prefix in their names). It is worth to note the [binfmt_script](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/binfmt_script.c?h=linux-4.14.y) module, which is responsible for parsing above mentioned shebang lines and  executing scripts on the target system (not everyone knows that the shebang support is actually implemented in the kernel itself and not in the shell or other daemon/process).

### Extending supported binary formats from userspace
But since we concluded that shebang is not the best option for our Go scripting, seems we need something else. Surprisingly Linux kernel already has a ["something else" binary support module](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/fs/binfmt_misc.c?h=linux-4.14.y), which has an appropriate name `binfmt_misc`. The module allows an administrator to dynamically add support for various executable formats directly from userspace through a well-defined `procfs` interface and is [well-documented][binfmt-iface].

Let's follow [the documentation][binfmt-iface] and try to setup a binary format description for `.go` files. First of all the guide tells you to mount special `binfmt_misc` filesystem to `/proc/sys/fs/binfmt_misc`. If you're using relatively recent systemd-based Linux distribution, it is highly likely the filesystem is already mounted for you, because systemd by default installs special [mount](https://github.com/systemd/systemd/blob/master/units/proc-sys-fs-binfmt_misc.mount) and [automount](https://github.com/systemd/systemd/blob/master/units/proc-sys-fs-binfmt_misc.automount) units for this purpose. To double-check just run:

```sh
$ mount | grep binfmt_misc
systemd-1 on /proc/sys/fs/binfmt_misc type autofs (rw,relatime,fd=27,pgrp=1,timeout=0,minproto=5,maxproto=5,direct)
```

Another way is to check if you have any files in `/proc/sys/fs/binfmt_misc`: properly mounted `binfmt_misc` filesystem will create at least two special files with names `register` and `status` in that directory.

Next, since we do want our `.go` scripts to be able to properly pass the exit code to the operating system, we need the custom [gorun][gorun] wrapper as our "interpreter":

```sh
$ go get github.com/erning/gorun
$ sudo mv ~/go/bin/gorun /usr/local/bin/
```

Technically we don't need to move `gorun` to `/usr/local/bin` or any other system path as `binfmt_misc` requires full path to the interpreter anyway, but the system may run this executable with arbitrary privileges, so it is a good idea to limit access to the file from security perspective.

At this point let's create a simple toy Go script `helloscript.go` and verify we can successfully "interpret" it. The script:
```golang
package main

import (
	"fmt"
	"os"
)

func main() {
	s := "world"

	if len(os.Args) > 1 {
		s = os.Args[1]
	}

	fmt.Printf("Hello, %v!", s)
	fmt.Println("")

	if s == "fail" {
		os.Exit(30)
	}
}
```

Checking if parameter passing and error handling works as intended:
```sh
$ gorun helloscript.go
Hello, world!
$ echo $?
0
$ gorun helloscript.go gopher
Hello, gopher!
$ echo $?
0
$ gorun helloscript.go fail
Hello, fail!
$ echo $?
30
```

Now we need to tell `binfmt_misc` module how to execute our `.go` files with `gorun`. Following [the documentation][binfmt-iface] we need this configuration string: `:golang:E::go::/usr/local/bin/gorun:OC`, which basically tells the system: "if you encounter an executable file with `.go` extension, please, execute it with `/usr/local/bin/gorun` interpreter". The `OC` flags at the end of the string make sure, that the script will be executed according to the owner information and permission bits set on the script itself, and not the ones set on the interpreter binary. This makes Go script execution behaviour same as the rest of the executables and scripts in Linux.

Let's register our new Go script binary format:

```sh
$ echo ':golang:E::go::/usr/local/bin/gorun:OC' | sudo tee /proc/sys/fs/binfmt_misc/register
:golang:E::go::/usr/local/bin/gorun:OC
```

If the system successfully registered the format, a new file `golang` should appear under `/proc/sys/fs/binfmt_misc` directory. Finally, we can natively execute our `.go` files:

```sh
$ chmod u+x helloscript.go
$ ./helloscript.go
Hello, world!
$ ./helloscript.go gopher
Hello, gopher!
$ ./helloscript.go fail
Hello, fail!
$ echo $?
30
```

That's it! Now we can edit `helloscript.go` to our liking and see the changes will be immediately visible the next time the file is executed. Moreover, unlike the previous shebang approach, we can compile this file any time into a real executable with `go build`.

[go-scripts-github]: https://gist.github.com/posener/73ffd326d88483df6b1cb66e8ed1e0bd
[shebang]: https://en.wikipedia.org/wiki/Shebang_(Unix)
[gorun]: https://github.com/erning/gorun
[binfmt-iface]: https://www.kernel.org/doc/html/v4.14/admin-guide/binfmt-misc.html
