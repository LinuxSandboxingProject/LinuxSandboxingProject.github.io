## Welcome to the Linux Sandboxing Project

This project aims to provide general information about Linux sandboxing technologies and existing sandboxing solutions.
The goal of this project is to spread support for sandboxing in Linux applications.


### What is a sandbox and how can it be useful?

Sandboxing provides an isolated run-time environment for a target application. The intention of sandboxing is to limit the consequences of a successful attack by an adversary. This is especially important for applications that provide services in untrusted network environments or interpret data that originates from untrusted sources, like files on the internet. Programs that parse complex file formats are especially at risk of being compromised. Multimedia libraries are a common source of security vulnerabilities that can be exploited to run arbitrary code in applications that use those libraries. One of the largest attack surfaces of modern desktop systems is the web browser. As a result of this risk, the developers of common browser software have implemented sandboxing support in their code for years. The chromium sandbox is one of the most advanced sandbox implementations today and it is well documented too. There are many more application types that present a wide attack surface and that would benefit by a sandbox implementation. In the end every program should run only with the minimal privileges needed and sandboxing can help realize that where standard programming and operating utilities do not suffice.


### What a sandbox is NOT!!!

Sandboxing is not a substitution for clean and secure coding. The limit of a well implemented sandbox is to contain the damage caused by a compromise of the application that was attacked. However all data the sandboxed application has access to is compromised. Using a generic container sandbox like firejail to isolate a browser from the rest of the system, will still compromise all web logins and everything the browser is used to access, which is usually a great deal of personal and sensitive information. While it will still help to reduce the damage, everyone should be aware of the limits of sandboxing.


### Sandbox technologies

There are many ways to implement software in a secure way with minimal privileges and in recent years there have several valuable technologies been added to the Linux kernel that provide a great deal of isolation and security. One of the most promising features is the support for **seccomp BPF**. This "secure computing" feature provides a means to filter system calls that are available for a process. By reducing the number of syscalls a process can use to only those the application needs, the attack surface of the kernel can be significantly reduced. Additionally, reducing the available system interfaces will restrict the possibilities of exploit code to do damage. For example blocking the use of the _socket_ syscall, will prevent the process to access network functionality. An easy way to implement seccomp filter is by using the [libseccomp](https://github.com/seccomp/libseccomp) library. This way handling the complicated Berkeley Packet Filter language directly can be avoided.

Another technology that is mainly used by container services like docker, is Linux namespaces. This feature allows to isolate critical system resources like the file system or the process environment from the rest of the system. It can also be used to provide sandboxing as is the case with the chromium browser.

Last but not least there is also SELinux and AppArmor which provide features to restrict what an application is allowed to do on a system.


### Sandbox architectures

There are several different kinds of sandboxing architectures. A common sandbox is a general purpose container application that builds an isolated process environment and executes the target application inside it. One of those tools is [firejail](https://github.com/netblue30/firejail) which provides rules for common applications that can be further adopted by the user to fit their needs. This kind of application can be easily applied but also has several drawbacks. While it is possible to build custom environments for any application with this tool, it still remains a broad shell around the application that does not consider the internal workings of the target software. Building sandbox solution inside the target application itself, the resulting isolation can be significantly more restrictive. For example the rendering process of the chromium browser has basically no access to the rest of the system. This kind of sandboxing isolation is not possible with general purpose sandboxing tools. Additionally there the issue of using privileged features. _Firejail_ is an SUID application that runs with root privileges and never drops them completely. This has already lead to several local root exploits. A more sane approach is taken by the developers of the [bubblewrap](https://github.com/projectatomic/bubblewrap) project. This software provides unprivileged users with an easy way to use Linux namespaces. When the operating system of the user allows the unprivileged use of user namespaces this application can be run with normal user privileges. On systems without such support, it uses SUID in a conservative and careful way to provide the same functionality. There are also several other application that run as a privileged service and can provide similar functionality. Among them are _systemd-nspawn_, _docker_, _lxc_, _subgraph_, _rkt_ and _playpen_. It should be noted that malicious applications running inside a isolated container, can still escape the sandbox if a vulnerability in the kernel is exploited. To prevent this, the additional use of seccomp is advised. Fortunately many container applications like docker already have support for integrated seccomp filter rules. Virtualization can also be used to apply even stronger isolation as demonstrated by the [QubesOS](https://www.qubes-os.org/) project. The only attack surface remaining will be the Hyper-visor, which is significantly smaller then with container technology.

While all these general purpose sandboxing applications have their uses, there is another issue that they all have in common: they are optional. When an application has a need to be run in an isolated environment because it is at risk of being compromised, the isolation should not be be applied by additional tools. Not only does this mean that the user has to apply the additional isolation without knowledge of the software internals, which is questionable to begin with, it is also common that security features are among the first things that users disable whenever there is an issue with the application. The solution to this is a sandbox implementation that is application specific and build by the developers of the target software. By designing an application while considering secure design principles, the result will be much stronger then any general purpose solution. Apart from using secure software coding principles to begin with, there are also many Linux features that can be used to provide meaningful security. Before adding features like seccomp, using traditional user and process separation can significantly improve the application security. This is especially true for privileged application, as these can be separated, execution the majority of the code as an unprivileged user, while only a small portion of the code needs to run as a privileged process. This is demonstrated by the _openSSH_ project, which implemented privilege separation more then a decade ago, significantly reducing the consequences of vulnerabilities.


### Existing sandboxing tools

- [bubblewrap](https://github.com/projectatomic/bubblewrap)
- [firejail](https://github.com/netblue30/firejail)
- [playpen](https://github.com/thestinger/playpen)
...


Application deployment framework with sandbox support:

- [flatpak](https://github.com/flatpak/flatpak/wiki)


## Developing Sandboxes / Integrating native sandbox support in applications

When developing software, use of secure design principles has significant consequences and can greatly improve the resulting attack surface. To effectively use security features of modern operating systems for application specific sandbox support, it is critical to considers the internal design structures during development. One example of a secure design is the chromium browser as well as newer versions of firefox. While a browser application in general needs access to many features and system interfaces, the rendering engine that interprets data provided by websites does not. By using a separate renderer process, especially for plugins like flash, that process can be restricted. By using a broker process architecture, the renderer can be run without any privileges at all and all communication and resource request can go through a broker process that can determine what resources should be available to the sub process. By running separated and restricted processes as a different user, the native security features of Unix systems can take full effect.


### Integrating seccomp filter

Before seccomp support can be implemented in an existing application, it's resource requirements have to be analyzed. One very useful tool for this purpose is _strace_. Tracing the systemcalls and arguments of an application will reveal the used resources. It will also provide a complete list of the system calls the application uses, which can be used to implement seccomp support using [libseccomp](https://github.com/seccomp/libseccomp). To generate a syscall list, run the target application with `strace -qfc <program>` or use this useful [tool](https://github.com/seccomp/libseccomp/blob/master/tools/scmp_app_inspector) from the libseccomp project. To get a complete list of needed syscalls it is important to make use of all application features during this phase. By integrating this to be run during unit testing, the process can easily be automated. However when libraries and kernel versions change, the list of syscalls an application utilizes can change as well, therefore retesting the used system calls should not be neglected.
While the generate list of used system calls can be applied at the start of the target application, this should be only the beginning the the use of seccomp. While a once loaded seccomp filter list can not be made less restrictive during the lifetime of the process, it can be made more restrictive. After an application has been initialized, many syscalls are never used again and can be blocked as well. This is especially useful at the point right before the dangerous part of an application, like e.g. parsing a file. At this stage the allowed syscall list might be restricted to a point where even if a malicious file is loaded and an vulnerability is exploited, the resulting access the attacker gained is insignificant and no harmful code can be successfully executed. But even if this is not the case and the application repeatedly needs access to many system calls, the reduced kernel attack surface may very well prevent a successful root exploit. In that case an attack would need to exploit another process or service first before the kernel can be attacked. When used in combination with namespaces, this might also be impossible.     


## Linux desktop security weak points

There are several weak points on modern Linux desktop systems that may be used by an attacker to escalate privileges and to escape from an sandboxed environment. Some of those weak points originate from legacy software that can be avoided by switching to modern alternatives. By considering the remaining weak points and blocking access to vulnerable services, a sandbox can avoid those issues.


### X-Window-System

One of the most vulnerable aspects of Linux desktop systems is the X-Window-System. This legacy software service usually runs as root on any desktop system and all user application have access to it. Using a vulnerability in a service run as root will lead to an escalation of privileges and therefore presents a major risk.
However there is an even bigger issue with the X-Window-System that is also present when the service can be run with user privileges. All application can see the communication between every other application and the X-Server. This includes keyboard and mouse inputs. It is therefore trivial to capture all inputs from other applications, including passwords and other sensitive information. This key logging capability can not be effectively prevented as long as access to the X-Server is needed. More on this topic can be found [here](https://theinvisiblethings.blogspot.de/2011/04/linux-security-circus-on-gui-isolation.html).
There are two ways to avoid this issue: The first and recommended way is to switch to another window system like wayland. With this new display protocol, isolation between application input is present and although key logging is [not](https://github.com/MaartenBaert/wayland-keylogger) impossible it demands some additional steps and can easily be prevented by sandboxing.
The second way to isolate and prevent sandboxed programs to read sensitive input of other applications, is to run them in a separate window server like [xephyr](https://www.freedesktop.org/wiki/Software/Xephyr/). This is more a workaround then a solution but as long as support for the wayland protocol is not present in all major linux applications, the X-Windows-System will still need to be present.
It should be said that preventing keylogging of application input is only possible for those applications that do not use the X-Window Server other applications have access to. If an application uses the wayland protocol, although it's input can not be read by other applications, it can still read the input of applications using the X-Window-System. This can however be prevented by using sandboxing techniques like namespaces to block access to the X-Window-System, in case the sandboxed application does not need access to it (because it is not a gui application or it uses wayland). Communication with the X-Window-System is done via unix domain sockets. See the IPC section for further information.


### Pulseaudio

Pulseaudio is an audio server that has similar issues as the X-Window-Server when it comes to isolation and access permissions. As long as an application has access to this service it can freely access the microphone and speakers of the system. This can and is being used to spy on conversations as well as capture passwords by recording the keyboard sounds. Moreover audio can be used to transmit information out of band even when the system is not connected to the network. Therefore sandboxed application should not have access to this kind of service. Unfortunately some applications like new versions of firefox, demand pulseaudio in newer versions. One solution to work with these applications without installing or granting access to pulseaudio, is to use emulation software like [apulse](https://github.com/i-rinat/apulse). This will still grant access to audio hardware but eliminate a significant attack vector (pulseaudio). Even though access to any kind of (audio)hardware device should only be allowed if the target application needs it.
Isolating available devices with namespaces is one solution to this issue.


### Interprocesscommunication (IPC) - Unix domain sockets

Another system service that presents a problem for application isolation is the Dbus inter process service. This service allows applications to communicate with each other and exchange information but there are usually no access control features active on most systems. This means communication between all applications of a single user is possible, something that should be prevented for effective sandboxing. Like other services like the X-Window-Server and pulseaudio, dbus uses unix domain sockets to communicate with other processes. Unix domain sockets are local socket files that use the same access control features as normal files. However access to the dbus socket is permitted for anyone. Even if the sandboxed application makes use of the dbus service, many programs can still be used without it. Since access to dbus is pretty much equivalent with escape from the sandbox, access to it's sockets should be blocked, just like with other problematic services like the X-Window-System and pulseaudio. By blocking those sockets on file system level e.g. by using mount namespaces, access to the service can be blocked. However there is a catch when it comes to unix domain sockets. On Linux there is another kind of sockets called abstract sockets, that are often used in addition to file based sockets. The problem with abstract sockets is that they do not exists as files and can therefore not be blocked on file system level. The only effective way to block abstract sockets, is to use a network namespace. This will prevent access to these abstract sockets and therefore communication with other services and applications.


### Setuid root

SUID applications are executed with system privileges but can be run by normal users. They are used to enable unprivileged users to make use of system functions that normally require root privileges. When such applications are designed in a secure way that only allows for the intended function to be executed with root privileges, this is not an issue. However if vulnerabilities are present this allows normal users to gain root privileges. Therefore this presents a major weak point on Linux systems that is often used by local root exploits.
There are several sandboxing techniques that prevent the use of this suid bit to elevate privileges. Seccomp for example requires the no_new_privs flag to be set which prevents the sandboxed process to gain more privileges then it originally started with. Bubblewrap also make use of this flat. Mounting the filesystem with nosuid is also a valid way to prevent the execution of suid applications.


### Ptrace

Ptrace can be used to manipulate the execution of other processes. While it is intended to be used for observing and debugging processes, is is also a dangerous function/syscall that can be used for elevated exploitation techniques. Preventing the use of ptrace inside a sandbox as well as preventing the use of ptrace on the sandboxed process is vital to enable effective isolation.


### Kernel interfaces

User space applications can interact with the kernel via system calls. While there are several hundred syscalls available, most applications only use a small subset of those syscalls. Vulnerabilities in the kernel can be exploited by accessing the affected system calls. However by limiting the number of syscalls that a process has access to, the attack surface of the kernel can be significantly reduced. By using seccomp syscall filter, the number of available syscalls can be influenced. While limiting certain syscalls can reduce the impact of malware in general, it will always limit the attack surface of the kernel by blocking access to kernel functions the application does not need.



(Section under construction)



## Application type and sandboxability

pdf apps as example

### Classical desktop app - evince

- issues of large functionality and several windows, restructuring needed
- too many dependencies and use cases to test everything

### Minimal desktop app - mupdf

- sandboxing possible with minor drawbacks


### non graphical app - pdftotext

- only dependency/problem is library dependency/changing syscalls

- solution is pledge like filter


### Combining broker architecture and seccomp

- splitting the process in broker and renderer will result in effective sandboxing

- check on ipc, needs to be carefully designed


### Sandbox vs. container

- Docker, lxc ...


### Issues and the future of Sandboxing

- Seccomp is too granular for easy and maintainable sandboxing (syscalls change too often)

- Pledge gives a great example



### Documentations

- [chromium sandbox](https://chromium.googlesource.com/chromium/src/+/master/docs/linux_sandboxing.md)
- [firefox sandbox](https://wiki.mozilla.org/Security/Sandbox), [firefox servo engine sandbox](https://github.com/servo/servo/wiki/Linux-sandboxing)
- [openSSH privilege separation](http://www.citi.umich.edu/u/provos/ssh/privsep.html)
...
