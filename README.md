<img width="500" height="200" alt="tumblr_inline_p8xrzbqzpD1t1bqu1_500-4034897272" src="https://github.com/user-attachments/assets/4a630361-3c1d-4501-83b1-3c6600e4fa9d" />


# How to Build & Use
git clone https://github.com/justmedusty/cypher.git OR download source 

cd cypher
cmake .
make

(optional) sudo cp cypher /bin

Usage is simple :

cypher operation secret pad

$ ./cypher encrypt "what the fuck is up kyle" 0x123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789
WARN:Be wary using modern intel or amd chips, they have a known management engine backdoor. If this secret is of life or death stakes, do not use this machine!
0x655C370CBAC8B694032312EAC0ED8661142308BAD7A79D65

]$ ./cypher decrypt 0x655C370CBAC8B694032312EAC0ED8661142308BAD7A79D65 0x123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789
WARN:Be wary using modern intel or amd chips, they have a known management engine backdoor. If this secret is of life or death stakes, do not use this machine!
Secret: what the fuck is up kyle

All pads AND encrypted secrets require the 0x prefix and must be in hex format.

How secure you want this to be is up to you. A proper implementation of one time pad is unbreakable. The keys need to be as random as possible, generated from a good source of entropy. They should only be used once,
then destroyed. You must pass the keys off in secure manner, you can preselect keys that are longer than what you really need, cypher will just trim off any extra key material. This can be a basic toy for encrypting basic messages or it could be a serious tool that could evade even the most sophisticated surveillance techniques.

I recommend using a linux operating system with my simple key generator tool here : https://github.com/justmedusty/keymaker

## Here is an example of maximum security:
- Offline (no radio transceiver onboard ideally, but it is okay if there is just ensure it's offline) rv64 or rv32 (could be an old mips, ppc like ps3 linux any old chip that does not have a management engine) to run this actual program alongside keymaker.

- Generate the key and encrypt the message PURELY in volatile memory, do not EVER let the unencrypted message touch the disk it should only ever touch terminal buffers and be cleared shortly after

- Move the message with a secure USB (be wary of the firmware, buy it brand new at a store so it can't easily be intercepted and tampered with)

- Send the message to the recipient, and the reciepient should follow the same but in reverse, move the encrypted message to their offline rv64, rv32, mip ,ppc etc linux box for decryption in volatile memory only

- You can send the message over any medium, even posting it on their facebook wall, but this depends on if you need to hide the fact you are communicating, if you do all else correct, you could write the encrypted message on your garage door and nobody could ever decipher it

### Sharing the pads
- For sharing pads, you can generate several pads and send them a few different ways: You could embed them inside an image, and encrypt said image (or encrypt the pads and send encrypted pads inside an image), you should send over I2P , Tor , or in person. If sent over Tor, I2P, open up a temporary service on tails or similar and whitelist your recipients public key so that access is cryptographically restricted on top of the brief time spent up, share keys pre-encrypted with the others PK

- Do not ever decrypt the pads on disk, ever ever ever. Decrypt them in memory when the time comes, and copy paste from pty buffer and clear it after, ideally write junk into it or reboot the machine. 

- Only read the message with your eyes, do not write it down or save it on disk

- You can also physically write down the keys in hex format and share keys in person, this is more arduous but it's an option. You could also encrypt them with the receipients public gpg key and leave a pad or a few on a drive in the woods for them to pick it up at a later date.

- If you are storing even encrypted pads on disk and the stakes are VERY high, you will want to write over the physical blocks it occupied many times (10-20 times just to be absolutely safe)

- It should be noted that for your encryption of pads, you should ALWAYS use AES 256 for your symmetric cipher, AES 128 is not quantum safe.

- It may be advisable to immediately power cycle your offline controlled arch hardware after decryption in volatile memory to be absolutely certain no side channel attacks can take place


# Final Note
This example is very extreme, and most people will not care to go that far, it is just meant as an illustration for how to use my tool pair as securely as possible. Your privacy is in your hands and only you know the stakes, make your own decisions but use your brain and don't give in to more than a reasonable compromise given your situation. The usefulness and security of these tools is entirely up to you, if you are just trying to hide passwords from someone you share your computer with, you could use this to hide it with relative ease assuming they are not super saavy. Just hiding your facebook password from a roommate you share a computer withcould be as simple as running cypher encrypt "myfaceB00kPassword123" 0x123456789ABCDEF123456789ABCDEF and storing that resulting hex value on disk, being able to easily remember the hex value. However, if a nation state is on your tail, you will need the full shebang.

