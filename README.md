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
