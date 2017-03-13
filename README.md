## Welcome to the Linux Sandboxing Project

This project aims to provide general information about Linux sandboxing technologies and existing sandboxing solutions.
The goal of this project is to spread support for sandboxing in Linux applications.


### What is a sandbox and how can it be useful?

Sandboxing provides an isolated run-time environment for a target application. The intention of sandboxing is to limit the consequences of a successful attack by an adversary. This is especially important for applications that provide services in untrusted network environments or interpret data that originates from untrusted sources, like files on the internet. Programs that parse complex file formats are especially at risk of being compromised. Multimedia libraries are a common source of security vulnerabilities that can be exploited to run arbitrary code in applications that use those libraries. One of the largest attack surfaces of modern desktop systems is the web browser. As a result of this risk, the developers of common browser software have implemented sandboxing support in their code for years. The chromium sandbox is one of the most advanced sandbox implementations today and it is well documented too. There are many more application types that present a wide attack surface and that would benefit by a sandbox implementation. In the end every program should run only with the minimal privileges needed and sandboxing can help realize that where standard programming and operating utilities do not suffice.


### What a sandbox is NOT!!!

Sandboxing is not a substitution for clean and secure coding and application design. The limit of a well implemented sandbox is to contain the damage caused by a compromise of the application that was attacked. However all data the sandboxed application has access to is compromised. Using a generic container sandbox like firejail to isolate a browser from the rest of the system, will still compromise all web logins and everything the browser is used to access, which is usually a great deal of personal and sensitive information. While it will still help to reduce the damage, everyone should be aware of the limits of sandboxing.


### Sandbox technologies

There are many ways to implement software in a secure way with minimal privileges and in recent years there have several valuable technologies been added to the linux kernel that provide a great deal of isolation and security. One of the most promising features is the support for **seccomp BPF**. This "secure computing" feature provides a means to filter system calls that are available for a process. By reducing the number of syscalls a process can use to only those the application needs, the attack surface of the kernel can be significantly reduced. Additionally, reducing the available system interfaces will restrict the possibilities of exploit code to do damage. For example blocking the use of the _socket_ syscall, will prevent the process to access network functionality. An easy way to implement seccomp filter is by using the [libseccomp](https://github.com/seccomp/libseccomp) library. This way handling the complicated Berkeley Packet Filter language directly can be avoided.

Another technology that is mainly used by container services like docker, is Linux namespaces. This feature allows to isolate critical system resources like the file system or the process environment from the rest of the system. It can also be used to provide sandboxing as is the case with the chromium browser.

Last but not least there is also SELinux and AppArmor which provide features to restrict what an application is allowed to do on a system.


### Sandbox architectures

There are several different kinds of sandboxing architectures. A common sandbox is a general purpose container application that builds an isolated process environment and executes the target application inside it. One of those tools is _[firejail]_(https://github.com/netblue30/firejail) which provides rules for common applications that can be further adopted by the user to fit their needs. This kind of application can be easily applied but also has several drawbacks. While it is possible to build custom environments for any application with this tool, it still remains a broad shell around the application that does not consider the internal workings of the target software. Building sandbox solution inside the target application itself, the resulting isolation can be significantly more restrictive. For example the rendering process of the chromium browser has basically no access to the rest of the system. This kind of sandboxing isolation is not possible with general purpose sandboxing tools. Additionally there the issue of using privileged features. _Firejail_ is an SUID application that runs with root privileges and never drops them completely. This has already lead to several local root exploits. A more sane approach is taken by the developers of the _[bubblewrap]_(https://github.com/projectatomic/bubblewrap) project. This software provides unprivileged users with an easy way to use linux namespaces. When the operating system of the user allows the unprivileged use of user namespaces this application can be run with normal user privileges. On systems without such support, it uses SUID in a conservative and careful way to provide the same functionality. There are also several other application that run as a privileged service and can provide similar functionality. Among them are _systemd-nspawn_, _docker_, _lxc_, _subgraph_, _rkt_ and _playpen_. Virtualization can also be used to apply even stronger isolation as demonstrated by the _QubesOS_ project.

While all these general purpose sandboxing applications have their uses, there is another issue that they all have in common: they are optional. When an application has a need to be run in an isolated environment because it is at risk of being compromised, the isolation should not be be applied by additional tools. Not only does this mean that the user has to apply the additional isolation without knowledge of the software internals, which is questionable to begin with, it is also common that security features are among the first things that users disable whenever there is an issue with the application. The solution to this is a sandbox implementation that is application specific and build by the developers of the target software. By designing an application while considering secure design principles, the result will be much stronger then any general purpose solution. Apart from using secure software coding principles to begin with, there are also many linux features that can be used to provide meaningful security. Before adding features like seccomp, using traditional user and process separation can significantly improve the application security. This is especially true for privileged application, as these can be separated, execution the majority of the code as an unprivileged user, while only a small portion of the code needs to run as a privileged process. This is demonstrated by the _openSSH_ project, which implemented privilege separations more then a decade ago, significantly reducing the consequences of programming errors.       


### Existing sandboxing tools

- [bubblewrap](https://github.com/projectatomic/bubblewrap)
- [firejail](https://github.com/netblue30/firejail)
- [playpen](https://github.com/thestinger/playpen)

...
(todo)



### Developing Sandboxes / Integrating native sandbox support in applications

(todo)
