# MDX_avail research
avail.exe is a binary that has been discovered on Middlesex Univerisity London systems. It is a poorly written executable that with the right spoofed UDP packet can trigger a packet flood.
When reciving a UDP packet on port 54321, it will take the first 4 characters of the username of the logged in user and reply back using the same port to the SRC.
Unfortuantly, using a network's broadcast address as SRC also works, leading to the main vulnerability.

Howlround is a tool designed to exploit this poorly written executable, named after the effect that occurs in audio systems - try looping back a speaker into a microphone to see what I'm talking about.

As Middlesex University London's systems are designed to run on a "deep-freeze" thin-client system, where the PCs reset upon each reboot or logout, this poorly written executable - possibily put there on purpose? - was introduced
on the sanitry source machine. As such, either a IT intern has screwed up badly, or the IT department has been comprmised. Either way, should the students of Middlesex University really trust the incomptant IT department with their
data, personal details, etc? What other faults exist within the system that we're not aware of if they leave badly written executables like avail.exe on the system? I wouldn't trust them myself to be honest. But then again,
that's just me.

Avail.exe hashes:
- SHA-256 hash: 1bcb43d7200fa4bb45a78b4ff27f075589d58fcd47f2147cfca8ae71078ad13f
- SHA-1 hash: 48693f045c9c42a695d23c8cbc3d4f590773a50d
- MD5 hash: 2392398f2b2550a7a3e17039820534e1
