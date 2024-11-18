# Projekt do predmetu ISA - Monitorovanie DNS komunikácie
Autor: Tímea Adamčíková <br>
Login: xadamc09 <br>
Dátum: 18.11.2024 

Program je schopný spracovať sieťovú komunikáciu v protokole DNS (Domain name Server), buď to z už existujúceho súboru vo formáte PCAP, alebo zo sieťovej komunikácie odchytávanej v reálnom čase zo zvoleného sieťového rozhrania. Vypisuje extrahované informácie o DNS správach na štandardný výstup, buď v jednoduchom, alebo kompletnom formáte. Dokáže vyhľadať a do súbora zapísať doménové mená a/alebo preklady doménových mien na IP adresy. 

### Odovzdaný archív
Odovzdaný archív obsahuje:
* zdrojové súbory (.h/.cpp)
* Makefile
* manual.pdf
* README.md - tento súbor
* priečinok tests, ktorý obsahuje testy a spustiteľný skript

### Spustenie
#### ./dns-monitor `(-i <interface> | -p <pcapfile>)` `[-v]` `[-d <domainsfile>]` `[-t <translationsfile>]`
popis parametrov:
* `-i <interface>` – názov rozhrania, na ktorom bude program načúvať, alebo
* `-p <pcapfile>` – názov súbora vo formáte PCAP, ktorý bude program spracovávať.
* `-v` – voliteľný parameter – kompletný výpis detailov o DNS správach.
* `-d <domainsfile>` – voliteľný parameter – názov súbora, do ktorého sa budú vypisovať doménové mená.
* `-t <translationsfile>` – voliteľný parameter – názov súbora, do ktorého sa budú vypisovať preklady doménových mien na IP.

### Príklady spustenia
1. **./dns-monitor -p tests/test\_a.pcap -t translations.txt -d domains.txt** <br>
*(štandardný výstup)* <br>
2024-10-20 16:50:55 192.168.0.89 -> 192.168.0.1 (Q 1/0/0/0) <br>
2024-10-20 16:50:55 192.168.0.1 -> 192.168.0.89 (R 1/1/0/0) <br> <br>
**cat translations.txt** <br>
vut.cz 147.229.2.90 <br> <br>
**cat domains.txt** <br>
vut.cz

2. **./dns-monitor -p tests/test\_a.pcap -v** <br>
*(štandardný výstup)* <br>
Timestamp: 2024-10-20 16:50:55 <br>
SrcIP: 192.168.0.89 <br>
DstIP: 192.168.0.1 <br>
SrcPort: UDP/53575 <br>
DstPort: UDP/53 <br>
Identifier: 0x1BAB <br>
Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, AD=0, CD=0, RCODE=0 <br> <br>
[Question Section] <br>
vut.cz. IN A <br>
==================== <br>
Timestamp: 2024-10-20 16:50:55 <br>
SrcIP: 192.168.0.1 <br>
DstIP: 192.168.0.89 <br>
SrcPort: UDP/53 <br>
DstPort: UDP/53575 <br>
Identifier: 0x1BAB <br>
Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, AD=0, CD=0, RCODE=0 <br> <br>
[Question Section] <br>
vut.cz. IN A <br> <br>
[Answer Section] <br>
vut.cz. 5 IN A 147.229.2.90 <br>
==================== 

3. *(1. terminál)* **sudo ./dns-monitor -i lo** <br>
*(2. terminál)* **nslookup vut.cz** <br>
*(štandardný výstup 1. terminál)* <br>
2024-11-17 15:35:31 10.255.255.254 -> 10.255.255.254 (Q 1/0/0/0) <br>
2024-11-17 15:35:31 10.255.255.254 -> 10.255.255.254 (R 1/1/2/4) <br>
2024-11-17 15:35:31 10.255.255.254 -> 10.255.255.254 (Q 1/0/0/0) <br>
2024-11-17 15:35:31 10.255.255.254 -> 10.255.255.254 (R 1/0/1/0)
