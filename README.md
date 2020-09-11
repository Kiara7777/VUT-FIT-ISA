# VUT FIT ISA

Projekt do předmětu Síťové aplikace a správa sítí na VUT FIT, 5. semestr, zima

## FTP/SSH Honeypot

Vytvořte nástroj typu honeypot simulující reálný FTP nebo SSH server. Nástroj bude po spuštění v jednom ze dvou režimů (FTP/SSH) naslouchat na specifikované IP adrese a TCP portu. Při pokusu o přihlášení klienta bude do textového logovacího souboru zaznamenána tato událost společně s uživatelským jménem a heslem, které klient zadal. Nástroj bude podporovat protokoly IPv4 i IPv6. Typ IP protokolu bude detekován automaticky dle zadané IP adresy. Funkcionalitu si vyzkoušejte na běžně dostupných FTP/SSH klientech.

Pro jednodušší implementaci SSH varianty můžete použít API knihovny libssh. FTP variantu implementujte čistě pomocí BSD socketů.

Kromě knihovny libssh a souvisejících hlavičkových souborů je dále je povoleno použít hlavičkové soubory pro zpracování parametrů (getopt.h), pro práci s řetězci, pro práci se sokety a další obvyklé funkce používané v síťovém prostředí (netinet/*, sys/*, arpa/* apod.), knihovnu pro práci s vlákny (libpthread), signály, časem, stejně jako standardní knihovnu jazyka C, C++ a STL. Další knihovny (kromě těch, které budou explicitně povoleny na fóru) jsou zakázány!

### Základní informace
Server implementujte jako konkurentní. Maximální počet současně přihlášených uživatelů bude definován pomocí spouštěcího parametru. Zápis do logovacího souboru ošetřete vhodnými synchronizačními prostředky. Zápis proběhne vždy jednorázově po zjištění všech potřebných údajů - čekání na zadání hesla nesmí blokovat jiné připojené klienty.

Spouštění:
- ./fakesrv -m mode -a addr -p port -l logfile [-r rsakey] [-c maxclients] [-t maxattempts]

Pořadí parametrů je libovolné. Popis spouštěcích parametrů:
- Povinný parametr -m definuje režim serveru: ftp nebo ssh.
- Povinný parametr -a slouží ke specifikování IP adresy, na které bude server naslouchat.
- Povinný parametr -p slouží ke specifikování TCP portu, na kterém bude server naslouchat.
- Povinný parametr -l slouží ke specifikování logovacího souboru.
- Parametr -r je povinný pouze v SSH režimu a slouží ke specifikování soukromého RSA klíče.
- Nepovinný parametr -c slouží ke specifikování maximálního počtu souběžně připojených klientů. Výchozí hodnota je 10 (maximální počet klientů v případě nezadání parametru -c).
- Nepovinný parametr -t slouží v režimu SSH ke specifikování maximálního počtu pokusů o zadání hesla v rámci jednoho připojení. Výchozí hodnota je 3 (maximální počet pokusů v případě režimu SSH a nezadání parametru -t).
- Spuštění programu bez parametrů nebo s neplatnými parametry vypíše nápovědu.

### Režim FTP
Server bude vyžadovat autentizaci pomocí uživatelského jména a hesla dle RFC 959. Po zadání jakéhokoli hesla server pošle klientovi zprávu "530 Login Incorrect" a ukončí spojení. Pro účely honeypotu není potřeba navazovat spojení na datovém portu.

příklad spuštění:
- ./fakesrv -m ftp -a fe80::21e:67ff:ab1a:b1ff -p 21 -l ftp.log -c 10

### Režim SSH
Server bude vyžadovat autentizaci pomocí uživatelského jména a hesla dle RFC 4253. Po zadání hesla se bude chovat, jako by heslo bylo chybné a bude vyžadovat nové zadání hesla až do vyčerpání všech pokusů o přihlášení.

příklad spuštění:
- ./fakesrv -m ssh -a 1.2.3.4 -p 22 -r ~/my_rsa.key -l ssh.log -t 5 -c 5

Výstup do logovacího souboru
Každý pokus o přihlášení bude zaznamenán do logovacího souboru (1 řádek = 1 záznam). Záznam bude obsahovat následující parametry (oddělené mezerami):
- Typ protokolu: FTP/SSH
- Datum ve formátu YYYY-MM-DD
- Čas ve formátu HH:MM:SS
- IP adresa klienta
- Uživatelské jméno zadané klientem
- Heslo zadané klientem
- Konce řádků budou v Unixovém formátu. Kromě uvedených parametrů, mezer a znaku pro nový řádek nebude logovací soubor obsahovat nic dalšího!

Příklad logovacího souboru
- SSH 2015-09-23 16:47:17 83.167.20.55 ihranicky 123456
- SSH 2015-09-23 16:48:22 83.167.20.55 ihranicky hesloheslo
- SSH 2015-09-23 17:02:41 82.151.19.87 opicak banan


