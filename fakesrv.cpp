#include <iostream>
#include <string>
#include <fstream>

#include <cstdlib>
#include <cstring>
#include <ctime>

#include <getopt.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>


#define DEBUG false //false true
#define DEBUG_SSH false //tohle je pro vypnuti a zapnuti moznosti SSH_BIND_OPTIONS_LOG_VERBOSITY_STR u SSH

#define MAXPORT 65535
#define MAXMESS 100

pthread_mutex_t mutexFile = PTHREAD_MUTEX_INITIALIZER; //pro zapis do souboru
pthread_mutex_t mutexCount = PTHREAD_MUTEX_INITIALIZER; //pro pocet pripojenych klientu

using namespace std;

/** NAPOVEDA vytiskne se pri neplatnych argumentech */
const string helpMsg =
"Program: FTP/SSH Honeypot\n"
"Ucel: Program simuluje prihlasovani na FTP/SSH server, logy zapisuje do daneho souboru\n"
"Autor: Sara Skutova (c) 2015\n"
"Pouziti:\n"
"./fakesrv -m mode -a addr -p port -l logfile [-r rsakey] [-c maxclients] [-t maxattempts]\n"
"Vysvetleni parametru:\n"
"POVINNY -m mode: rezim serveru ftp nebo ssh\n"
"POVINNY -a addr: IP adresa na ktere bude server naslouchat\n"
"POVINNY -p port: TCP port na ktere bude server naslouchat\n"
"POVINNY -l logfile: logovaci soubor\n"
"POVINNY POUZE S SSH -r rsakey: soukromy RSA klic\n"
"NEPOVINNY -c maxclients: max pripojenych klientu, default: 10\n"
"NEPOVINNY POUZE S SSG -t maxattempts: max pokusu o prihlaseni, default: 3\n"
"May the Force be with this project!\n";

/** Globalni file deskriptor */
ofstream logFile;

/** Pocet aktualne obsluhovanych klientu*/
int klientPocet = 0;

/** Stav programu */
enum stast
{
    SHELP,  //Vypsat napovedu
    SFTP,   //Rezim FTP
    SSSH    //Rezim SSH
};

/** Stav FTP*/
enum ftpStast
{
    WELCOME,    //privitat klienta
    USER,       //dostanu login
    PASS,       //dostanu heslo
    END         //ukonci spojeni s klientem
};

/** Chyby programu */
enum ecodes
{
    EOK,        //Vsechno OK
    EPARAM,     //Chyba v parametrech
    EGETADDR,   //Chyba pri getaddrinfo
    ESOCKET,    //Chyba pri vytvareni soketu
    EBIND,      //Chyba pri pripojovani soketu na port
    ENET,       //Celkova chyba pripojeni, bind se nedokazal napojit
    ELISTEN,    //Chyba pri konfiguraci naschlochani prichozich klientu
    EACCEPT,    //Chyba pri akceptovani pripojeni od klienta
    ERECV,      //Chyba pri cteni prijimane zpravy
    ESEND,      //Chyba pri odesilani zpravy
    ECLIENTCON, //Klient neocekavane prerusil spojeni
    ETHREAD,    //Vlakno se nevytvorilo
    EOPEN,      //Zadany soubor se nepodarilo vytvorit/otevrit
    EEXCHANGE,  //vymena klicu
    ESSHNEW,    //Chyba pri vytvareni ssh sessions nebo ssh bind
    EBINDOPTION,//Chyba pri konfiguraci bind pri ssh
    ECLIENTADDR, //Nepodarilo se ziskat adresu klieta
    ESSHINIT,    //Chyba pri inicializaci globalni kryptograficke struktury
    EMAXCLIENT, //Prekrocen maximalni pocet klientu, klient navic odpojen
    EUNKNOWN    //Neznama chyba
};

/** Chybove zpravy do dany kon chyby*/
const char *ecodeMsg[] =
{
    "Vse v poradku\n",                                                                          //EOK
    "Chyba v parametrech\n",                                                                    //EPARAM
    "Chyba u funkce getaddrinfo. Je IP adresa v poradku?\n",                                    //EGETADDR
    "Chyba pri vytvareni soketu: socket()\n",                                                   //ESOCKET
    "Chyba pri pripojovani soketu na port: bind()\n",                                           //EBIND
    "Celkova chyba pripojeni, bind se nedokazal napojit\n",                                     //ENET
    "Chyba pri konfiguraci naschlouchani prichozich klientu: listen()/ssh_bind_listen()\n",     //ELISTEN
    "Chyba pri akceptovani pripojeni od klienta: accept()\n",                                   //EACCEPT
    "Chyba pri cteni prijimane zpravy: recv()\n",                                               //ERECV
    "Chyba pri odesilani zpravy: send()\n",                                                     //ESEND
    "Klient neocekavane ukoncil spojeni\n",                                                     //ECLIENTCON
    "Vlakno se nevytvorilo: pthread_create()\n",                                                //ETHREAD
    "Zadany soubor se nepodarilo vytvorit/otevrit\n",                                           //EOPEN
    "Problem pri vymene klicu, ssh_handle_key_exchange()\n",                                    //EEXCHANGE
    "Chyba pri vytvareni ssh sessions nebo ssh bind: ssh_new()\n",                              //ESSHNEW
    "Chyba pri konfiguraci bind pri ssh: ssh_bind_options_set()\n",                             //EBINDOPTION
    "Nepodarilo se ziskat adresu klieta\n",                                                     //ECLIENTADDR
    "Chyba pri inicializaci globalni kryptograficke struktury: ssh_init()\n",                   //ESSHINIT
    "Prekrocen maximalni pocet klientu, klient navic odpojen\n",                                //EMAXCKLIENT
    "Neznama chyba\n"                                                                           //EUNKNOWN

};

/** Struktura pro parametry*/
typedef struct params
{
    int state;                  //Stav programu, dle vyctu stast
    int ecode;                  //Chybovy stav, dle vyctu ecodes
    string addr;                //Adresa na jake se bude pripojovat
    string port;                   //Cislo portu na jekem bude naplouchat
    string logfile;             //logovaci soubor
    string key;                 //RSA klic
    int maxClient;              //maximalni pocet najednou pripojenzch klientu
    int maxAuth;                //maxilamni pokus o prihlaseni

}PARAMS;

/** Struktura pro argumenty pro funkci kterou pouzicaji FTP vlakna*/
typedef struct ftpArg
{
    int clientSoketArg;
    string clientAddrArg;

}FTPARG;

/** Struktura pro argumenty pro funkci kterou pouzicaji SSH vlakna*/
typedef struct sshArg
{
    ssh_session sshsessionArg;
    string clientAddrArg;
    int pocetAuth;

}SSHARG;

/**
 * Vytiskne chybove hlaseni na stderr, dle chyboveho kodu
 * @param ecode kod chyby, odpovida vyctu ecodes
 */
 void printEcode(int ecode, int state)
 {
     if (ecode < EOK || ecode > EUNKNOWN)
        ecode = EUNKNOWN;

     cerr << ecodeMsg[ecode];

     if (state == SHELP)
        cerr << helpMsg;
 }
/**
 * Zpracuje parametry prikazove radky a vrati je ve strukture
 * @param argc pocet parametru
 * @param argv pole s parametry
 * @return result struktura s parametry
 */
PARAMS getParams(int argc, char *argv[])
{
    //pouzije se pro identifikaci povinnych parametru
    bool mod, addr, port, log, key, clients, auth;
    mod = addr = port = log = key = clients = auth = false;
    int portN = 0;

    PARAMS result =
    {
        SHELP, EOK, "", "", "", "", 10, 3
    };

    //./fakesrv -m mode -a addr -p port -l logfile [-r rsakey] [-c maxclients] [-t maxattempts]
    //  1        2  3    4  5    6  7   8   9       10  11      12      13      14      15
    //nedostatecny pocet parametru nebo az moc parametru
    if (argc < 9 || argc > 15)
    {
        result.ecode = EPARAM;
        result.state = SHELP;
        return result;
    }

    int c;
    char *pEnd; //pro prevod retezcu na cisla
    opterr = 0; //aby getopt nevypisoval chyby

    while((c = getopt(argc, argv, "m:a:p:l:r:c:t:")) != -1)
    {
        switch(c)
        {
            case 'm':
                if (mod)//opakujici se parametr
                {
                    result.ecode = EPARAM;
                    return result;
                }
                //jaky mod
                //ten prevod na string - aby mi nerval prekladac, ze to muze zpusobovat neocekavane chovani
                if (string(optarg) == "ftp" || string(optarg) == "FTP")
                    result.state = SFTP;
                else if (string(optarg) == "ssh" || string(optarg) == "SSH")
                    result.state = SSSH;
                else
                {
                    //pro pripad kdyby tam nebylo ani ftp ani ssh, ale neco naprosto jineho
                    result.ecode = EPARAM;
                    return result;
                }

                mod = true;
                break;

            case 'a':
                if (addr)
                {
                    result.ecode = EPARAM;
                    return result;
                }
                //adresa na jake se bude naslouchat
                result.addr = optarg;
                addr = true;
                break;

            case 'p':
                if (port)
                {
                    result.ecode = EPARAM;
                    return result;
                }
                //cislo portu na jakem se bude naslouchat
                //prevod retezce na cislo, v pEnd bude prvni pismeno co neni cislo, pokud bude prazdne - OK
                portN = strtol(optarg, &pEnd, 10); //poze kontrola, port potrebuju jako retezec
                if (*pEnd != '\0')
                {
                    result.ecode = EPARAM;
                    return result;
                }
                port = true;
                result.port = optarg;
                break;

            case 'l':
                if (log)
                {
                    result.ecode = EPARAM;
                    return result;
                }
                //logovaci soubor
                result.logfile = optarg;
                log = true;
                break;

            case 'r':
                if (key)
                {
                    result.ecode = EPARAM;
                    return result;
                }
                //RSA klic
                result.key = optarg;
                key = true;
                break;

            case 'c':
                if (clients)
                {
                    result.ecode = EPARAM;
                    return result;
                }
                //maximalni pocet klientu najednou propijenych, cislo - kontrolovat zda je to cislo
                result.maxClient = strtol(optarg, &pEnd, 10);
                if (*pEnd != '\0')
                {
                    result.ecode = EPARAM;
                    return result;
                }
                clients = true;
                break;

            case 't':
                if (auth)
                {
                    result.ecode = EPARAM;
                    return result;
                }                //maximalni pocet pokusu o prihlaseni, cislo - kontrolovat yda je to cislo
                result.maxAuth = strtol(optarg, &pEnd, 10);
                if (*pEnd != '\0')
                {
                    result.ecode = EPARAM;
                    return result;
                }
                auth = true;
                break;

            default:
                //pokud najde neco co tam nema byt, nebo tam neni to co tam ma byt
                result.ecode = EPARAM;
                result.state = SHELP;
                return result;

        }
    }

    //kontrola zda jsou zadany povinne parametry
    if (!mod || !addr || !port || !log)
    {
        result.ecode = EPARAM;
        return result;
    }

    //pri modu ssh, musi byt pritomen parametr -r
    if (result.state == SSSH && !key)
    {
        result.ecode = EPARAM;
        return result;
    }

    //ciselne parametry nesmi byt v minusu, port nesmi byt vetsi nez MAXPORT
    if (result.maxAuth < 0 || result.maxClient < 0 || portN < 0 || portN > MAXPORT)
    {
        result.ecode = EPARAM;
        return result;
    }

    //pri FTP nemuze byt -r nebo -t
    if (result.state == SFTP && (key || auth))
    {
        result.ecode = EPARAM;
        return result;
    }

    //otevrit soubor
    logFile.open(result.logfile.c_str(), ios_base::out | ios_base::app | ios_base::binary);

    if(!logFile.is_open())
    {
        result.ecode = EOPEN;
    }

    if (DEBUG)
    {
        cout << "getParams(): Paramatry dokonceny a soubor otevren" << endl;
    }

    return result;
}

/**
 * Ziska aktualni cas a pretrasformuje ho na pozadovany retezec
 * @return retezec s datem a casem
 */
 string logTime(void)
 {
    struct tm *local;
    time_t helptime;
    char helpcas[30];
    string cas;

    memset(&helpcas, 0, sizeof(helpcas));

    time(&helptime); //cas od epochy

    local = localtime(&helptime); //lokalni cas

    strftime(helpcas, 30, "%Y-%m-%d %H:%M:%S ", local); //30 - nahodne vybrano, mozna by stacilo i 21

    cas = helpcas;

    return cas;
}

/**
 * Ze soketu pripojeneho klienta se ziska jeho adresa
 * @param clientSoket - soket klienta
 * @param navrat - navratovy kod, pokud ok tak EOK
 * @return retezec s adresou
 */
string ipClientAddress(int clientSoket, int *navrat)
{
    string address;
    socklen_t addrLen;
    struct sockaddr_storage clientAddr;

    addrLen = sizeof(clientAddr);

    //ze soketu vytahnout adresu klienta
    if (getpeername(clientSoket, (struct sockaddr *) &clientAddr, &addrLen) == -1)
    {
        cout << "Chyba tu" << endl;
        *navrat = ECLIENTADDR;
        return address;
    }
    else
    {
        //tady se resi adresa klienta
        if (clientAddr.ss_family == AF_INET)
        {    //IPv4
            char help[INET_ADDRSTRLEN];
            struct sockaddr_in *client = (struct sockaddr_in *)&clientAddr;
            inet_ntop(AF_INET, &client->sin_addr, help, INET_ADDRSTRLEN); //prelozi adresu klienta na citelnejsi formu
            address = help;
        }
        else if (clientAddr.ss_family == AF_INET6)
        {    //IPv6
            char help[INET6_ADDRSTRLEN];
            struct sockaddr_in6 *client = (struct sockaddr_in6 *)&clientAddr;
            inet_ntop(AF_INET6, &client->sin6_addr, help, INET6_ADDRSTRLEN); //prelozi adresu klienta na citelnejsi formu
            address = help;
        }
    }

    if (DEBUG)
    {
        cout << "ipClientAddress(): Adresa klienta ziskana: " << address << endl;
    }

    *navrat = EOK;

    return address;
}

/**
 * Vytvori soket
 * @param int *socket - deskriptor soketu
 * @param struct addrinfo *pomoc - struktura s nastavenim pro sit
 * @return EOK - pokud je vse OK, jinak kod chyby
 */
int createSocket(int *soket, struct addrinfo *pomoc)
{
    if ((*soket = socket(pomoc->ai_family, pomoc->ai_socktype, pomoc->ai_protocol)) == -1)
    return ESOCKET;

    if (DEBUG)
    {
        cout << "createSocket():Soket vytvoren" << endl;
    }

    return EOK;
}

/**
 * Spoji soket s zadanym portem
 * @param soket - socket descriptor
 * @param *param - struktura s nastavenim pro sit
 * @return EOK - pokud vse OK, jinak kod chyby
 */
 int bindMe(int soket, struct addrinfo *pomoc)
 {
     if (bind(soket, pomoc->ai_addr, pomoc->ai_addrlen) == -1)
        return EBIND;

    if (DEBUG)
    {
        cout << "bindMe(): Soket navazan na port" << endl;
    }

     return EOK;
 }
/**
* Funkce funguje jako FTP komunikace, pomoci stavoveho automatu
* se bude rozhodovat, kterou zpravu odeslat.
*/
void *ftpCom(void *client)
{
    FTPARG *arg = (FTPARG*)client; // NEZAPOMEN TO UVOLNIT!!!!
    char clientMessage[MAXMESS];
    string mess, clientMess, username, password, zaznam, cas;
    int stav = WELCOME;
    int pocet;
    bool isTime = false;

    if (DEBUG)
    {
        cout << "ftpCom(): Zacina ftp kominukace " << arg->clientSoketArg << " " << arg->clientAddrArg << endl;
    }
    while(true)
    {
        memset(clientMessage, 0, sizeof(clientMessage));

        if (stav != WELCOME)
        {
            if ((pocet = recv(arg->clientSoketArg, clientMessage, MAXMESS, 0)) == -1) //cteni zpravy od klienta
                {
                    printEcode(ERECV, SFTP);
                    close(arg->clientSoketArg);
                    delete(arg);
                    pthread_exit(NULL);
                }

            if (pocet == 0) //klient ukoncil spojeni - SPATNE
            {
                printEcode(ECLIENTCON, SFTP);
                break;
            }
        }

        clientMess = clientMessage;
        if (DEBUG)
        {
            cout << "ftpCom(): Neco jsem od klienta precetl: " << clientMess << endl;
        }

        if (stav == WELCOME)
        {
            //privitat klienta, odeslat 220
            mess = "220 ISA_FTP_SARA WELCOME\r\n"; //220
            stav = USER;

        }
        else if (stav == USER)
        {
            //nejdriv overit zda skutecne prvni zprava byla USER
            size_t kde = clientMess.find("USER ");
            if (kde != string::npos && kde == 0)
            {
                //prijal jsem username ale chci i heslo
                mess = "331 Password required\r\n";

                //dostat ze spravy od klienta uzivatelske jmeno
                clientMess.erase(0,5); // smaze se USER + ta mezera
                clientMess.erase(clientMess.end() - 2, clientMess.end()); // snad to  vymaze konec neboli \r\n
                username = clientMess;

                stav = PASS;
            }
            else
                mess = "332 Need account for login\r\n";
        }
        else if (stav == PASS)
        {
            //mam heslo, ale je mi to jedno, papa
            mess = "530 Login incorrect\r\n";

            //dostat ze spravy od klienta heslo jmeno
            clientMess.erase(0,5); // smaze se PASS + ta mezera
            clientMess.erase(clientMess.end() - 2, clientMess.end()); // snad to  vymaze konec neboli \r\n
            password = clientMess;

            //od ted potrebuju aby se mi tam nikdo jiny - s jinym case nevecpal
            pthread_mutex_lock(&mutexFile); //zavrit mutex
            cas = logTime();
            isTime = true;

            //tvorba zaznamu, ktery se prida
            zaznam = "FTP " + cas + arg->clientAddrArg + " " + username + " " + password + "\n";

            logFile.write(zaznam.c_str(), zaznam.length());
            logFile.flush();

            pthread_mutex_unlock (&mutexFile);//otevrit mutex

            stav = END;
        }

        if (DEBUG)
        {
            cout << "ftpCom(): Pripravil jsem pro klienta zpravu: " << mess << endl;
        }

        if (send(arg->clientSoketArg, mess.c_str(), mess.length(), 0) == -1) //odeslani zpravy klientovi
        {
            printEcode(ESEND, SFTP);
            close(arg->clientSoketArg);
            delete(arg);
            pthread_exit(NULL);

        }

        if (DEBUG)
        {
            cout << "ftpCom(): Odeslal jsem klietovi zpravu" << endl;
        }

        //konci prace s klientem, PAPA klient - uzavri soket
        if (stav == END)
        {
            close(arg->clientSoketArg);
            if (DEBUG)
            {
                cout << "Klient: " << arg->clientSoketArg << " Bye..." << endl;
            }
            break;
        }

    }

    if (stav != END && !isTime) // nedobehlo to dokonce, klient se a asi predcasne odpojil
    {
        pthread_mutex_lock(&mutexFile); //zavrit mutex

        cas = logTime();
        close(arg->clientSoketArg);

        //tvorba zaznamu, ktery se prida
        zaznam = "FTP " + cas + arg->clientAddrArg + " " + username + " " + password + "\n";

        logFile.write(zaznam.c_str(), zaznam.length());
        logFile.flush();

        if (DEBUG)
        {
            cout << "ftpCom(): ZAZNAM zapsan do souboru: " << zaznam;
        }

        pthread_mutex_unlock (&mutexFile);//otevrit mutex
    }

    if (DEBUG)
    {
        cout << "ftpCom(): FTP vlakno KONEC" << endl;
    }

    delete(arg);
    pthread_mutex_lock(&mutexCount); //zavrit mutex
    klientPocet--;
    pthread_mutex_unlock(&mutexCount); //zavrit mutex
    pthread_exit(NULL);
}
/**
 * Funkce zachycuje a obsluhuje vsechny klienty
 * @param soket - socket descriptor
 * @param *param - parametry prizakove radky
 * @return EOK - pokud vse OK, jinak kod chyby
 */
int server(int soket, PARAMS *param)
{

    if (listen(soket, param->maxClient) == -1)
        return ELISTEN;

    if (DEBUG)
    {
        cout << "server(): Server posloucha na prichzi spojeni" << endl;
    }

    //pro informace o klientovi, soket klienta, delka adresy, adresa
    int clientSocket;
    socklen_t addrLen;
    struct sockaddr_storage clientAddr;
    int navrat;
    bool prijmonut = false;

    addrLen = sizeof(clientAddr);

    while(true)
    {
        pthread_t vlakno;
        //prijmovani klientu, vrati se soket deskriptor s pripojim na klienta
        if ((clientSocket = accept(soket, (struct sockaddr *) &clientAddr, &addrLen)) == -1)
            return EACCEPT;

        pthread_mutex_lock(&mutexCount); //zavrit mutex
        if (klientPocet < param->maxClient)
            prijmonut = true;
        else
            prijmonut = false;
        pthread_mutex_unlock(&mutexCount); //zavrit mutex

        if (prijmonut)//muzu oblouzit
        {
            //tvorba struktury pro argumenty pro funkci se kterou pracuji vlakna
            FTPARG *arguments = new FTPARG;
            arguments->clientSoketArg = clientSocket; //soket od klienta
            arguments->clientAddrArg = ipClientAddress(clientSocket, &navrat);

            if (navrat != EOK) //pokud se nepodari ziskat adresu, tak odpojim klienta - promin mas smulu
            {
                printEcode(navrat, param->state);
                close(clientSocket);
                delete(arguments);
                continue; //klient ma smulu, bude se obluhovat dalsi klient

            }

            if (pthread_create(&vlakno, NULL, ftpCom, (void *) arguments))
            {
                //vlakno se nevytvorilo, klient nebude obslouzen, bude mu zavre sokent
                printEcode(ETHREAD, param->state);
                close(clientSocket);
                delete(arguments);
            }

            pthread_mutex_lock(&mutexCount); //zavrit mutex
            klientPocet++;
            pthread_mutex_unlock(&mutexCount); //zavrit mutex
        }
        else //promin nemuzes
        {
            printEcode(EMAXCLIENT, SFTP);
            close(clientSocket);
        }



    }

    return EOK;
}

/**
 * Funkce prelozi/rozpozna danou adresu, a nasledne vola funkce ktere jsou
 * potreba k vytvoreni serveru
 * @param *param - parametry prikazove radky
 * @return EOK - pokud vse OK, jinak kod chyby
 */
int netWorkFTP(PARAMS *param)
{
    int soket, navrat;
    soket = navrat = 0;

    struct addrinfo hints, *servinfo, *pomoc;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC; //AF_INET, AF_INET6, AF_UNSPEC - rozhodne se dle adresy a service
    hints.ai_socktype = SOCK_STREAM; //sock_stream - tcp, sock_dgram - udp

    //tady v service info budou ulozeny vsechny moznosti co se nasly - seznam
    // napr. www.fit.vutbr.cz - najde se pro IPv4 i pro IPv6
    //brana v uvahu bude pouze moznost co se najde jako prvni
    if (getaddrinfo(param->addr.c_str(), param->port.c_str(), &hints, &servinfo) != 0)
        return EGETADDR;

    if (DEBUG)
    {
        cout << "netWork(): getaddrinfo prelozilo adresu, pouzije se protokol: ";

    }
    for (pomoc = servinfo; pomoc != NULL; pomoc = pomoc->ai_next)
    {
        //pokud to naslo validni zaznam, tak vyskoc
        if (pomoc->ai_family == AF_INET)
            break;
        else if (pomoc->ai_family == AF_INET6)
            break;

    }

    if (DEBUG)
    {
        if (pomoc->ai_family == AF_INET)
            cout << "IPv4" << endl;
        else if (pomoc->ai_family == AF_INET6)
            cout << "IPv6" << endl;
        else
            cout << "NEZNAMO, neco spatneho se stalo" << endl;
    }

    //vytvorit soket
    if ((navrat = createSocket(&soket, pomoc)) != EOK)
    {
        freeaddrinfo(servinfo);
        return navrat;
    }

    //napojit soket na dany port
    if ((navrat = bindMe(soket, pomoc)) != EOK)
    {
        freeaddrinfo(servinfo);
        return navrat;
    }

    //pokud se nic nenaslo, nenapojilo, nevytvorilo
    if (pomoc == NULL)
    {
        freeaddrinfo(servinfo);
        return ENET;

    }

    freeaddrinfo(servinfo); //uz tu dynamickou strukturu nepotrebujeme, muzeme ji uvolnit

    //funkce se stara o prichozi pripojeniod klientu
    if ((navrat = server(soket, param)) != EOK)
    {
        close(soket);
        return navrat;
    }

    close(soket);
    return EOK;
}

/**
 * SSH komunikace pro ziskani uzivatelkeho jmena
 * a hesla. Dale se zapisuje do souboru
 */
 void *sshCom(void *client)
 {
     SSHARG *arg = (SSHARG*)client;
     string username, passw, cas, zaznam;
     bool isTime = false;


     if (DEBUG)
     {
         cout << "sshCom(): Zacina SSH komunikace" << endl;
     }

    //AUTENTIZACE SERVERU - klic a pak AUTENTIZACE UZIVATELE - heslo
    if (ssh_handle_key_exchange(arg->sshsessionArg) != SSH_OK)
    {
        printEcode(EEXCHANGE, SSSH);
        ssh_disconnect(arg->sshsessionArg);
    }
    else
    {

        if (DEBUG)
        {
            cout << "sshCom(): Vymena klicu ukoncena" << endl;
        }

        ssh_message sshZprava;
        int metoda, typ;
        int pocetPrihlaseni = 0;

        while(true) //smycka pro prijem a odesilani zprav
        {
            //username.clear();
            passw.clear();
            cas.clear();
            zaznam.clear();
            isTime = false;

            if ((sshZprava = ssh_message_get(arg->sshsessionArg)) == NULL) //chyba nebo vyprsel timeout nebo se klient odpojil
                break;

            if (DEBUG)
            {
                cout << "sshCom():Ziskal jsem od klienta zpravu";
            }

            typ = ssh_message_type(sshZprava); //typy jsou definovany v libssh.h, potrebuju autorizaci SSH_REQUEST_AUTH

            if (typ == SSH_REQUEST_AUTH)//autorizacni zprava - autorizacnich metod je ale vice
            {
                if (DEBUG)
                {
                    cout << " a je to autorizacni zprava" << endl;
                }

                metoda = ssh_message_subtype(sshZprava); //ziskam autorizacni metodu, chci SSH_AUTH_METHOD_PASSWORD

                if (metoda == SSH_AUTH_METHOD_PASSWORD) // prihlasovani pomoci username a password
                {
                    if (DEBUG)
                    {
                        cout << "sshCom(): Autorizacni zprava s metodou pro login a heslo" << endl;
                    }
                    pocetPrihlaseni++;

                    username = ssh_message_auth_user(sshZprava);    //ziskat username
                    passw = ssh_message_auth_password(sshZprava);   //ziskat password

                    //nechci aby se tam vespal nekdo
                    pthread_mutex_lock(&mutexFile); //zavrit mutex

                    cas = logTime();    // ziskat datum a cas
                    isTime = true;

                    //tvorba zaznamu, ktery se prida
                    zaznam = "SSH " + cas + arg->clientAddrArg + " " + username + " " + passw + "\n";

                    logFile.write(zaznam.c_str(), zaznam.length());
                    logFile.flush();

                    if (DEBUG)
                    {
                        cout << "ZAZNAM zapsan: " << zaznam;
                    }

                    pthread_mutex_unlock (&mutexFile);//otevrit mutex

                    if (pocetPrihlaseni == arg->pocetAuth) //ukonci pokusy o prihlasovani
                        break;


                    ssh_message_auth_set_methods(sshZprava, SSH_AUTH_METHOD_PASSWORD); //zase posílam klientovi ze chci zpravu
                    ssh_message_reply_default(sshZprava);


                }
                else //jina metoda, kterou ale nechci
                {
                    //ssh_set_auth_methods(sshsession, SSH_AUTH_METHOD_PASSWORD); //kliente chci jenom tuhle metodu
                    ssh_message_auth_set_methods(sshZprava, SSH_AUTH_METHOD_PASSWORD);
                    ssh_message_reply_default(sshZprava);   //odpovedet klientovi

                    if (DEBUG)
                    {
                        cout << "sshCom(): Pro autentizaci se pouzila jina metoda nez chci, zaslal jsem klientovi info o metode" << endl;
                    }
                }



            }
            else
            {   // neni to autorizacni zprava
                ssh_message_reply_default(sshZprava);//pokud nebyla autentizacni zprava, tak po tehle odpovedi zprava uz bude

                if (DEBUG)
                {
                    cout << " a neni to autorizacni zprava, odeslal jsem klientovi negativni odpoved" << endl;
                }

            }

            ssh_message_free(sshZprava);

        } //konec while
    }
    ssh_disconnect(arg->sshsessionArg);
    if (DEBUG)
    {
        cout << "sshCom(): Spojeni s klientem ukonceno" << endl;
    }

    if (!isTime)
    {
        pthread_mutex_lock(&mutexFile); //zavrit mutex
        cas = logTime();
        //tvorba zaznamu, ktery se prida
        zaznam = "SSH " + cas + arg->clientAddrArg + " " + username + " " + passw + "\n";

        logFile.write(zaznam.c_str(), zaznam.length());
        logFile.flush();

        pthread_mutex_unlock (&mutexFile);//otevrit mutex

        if (DEBUG)
        {
            cout << "sshCom(): neco se pokazilo, ale mame ZAZNAM: " << zaznam;
        }



    }

    pthread_mutex_lock(&mutexCount); //zavrit mutex
    klientPocet--;
    pthread_mutex_unlock(&mutexCount); //zavrit mutex

    ssh_free(arg->sshsessionArg);
    delete(arg);
    pthread_exit(NULL);
 }



/**
 * Nakonfigure ssh server a bude prijimat jednotlive klienty
 */
int sshServer(PARAMS param)
{

    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    if (ssh_init() == -1) //chyba
        return ESSHINIT;
    ssh_session sshsession;
    ssh_bind sshbind = ssh_bind_new();

    if (DEBUG)
    {
        cout << "sshServer(): bind a session vytvoreny" << endl;
    }

    //nastaveni adresy, portu a klice, < 0 pri chybe
    if (ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, param.addr.c_str()) < 0 ||
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, param.port.c_str()) < 0 ||
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, param.key.c_str()) < 0)
    {
        ssh_bind_free(sshbind);
        return EBINDOPTION;

    }

    if (DEBUG_SSH) {ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");} //mluv se mnou demone

    if (DEBUG)
    {
        cout << "sshServer(): bind nakonfigurovan" << endl;
    }

    //naslouchani na pripojeni
    if (ssh_bind_listen(sshbind) < 0)
    {
        ssh_bind_free(sshbind);
        return ELISTEN;
    }

    if (DEBUG)
    {
        cout << "sshServer(): nasloucham na prichozi spojeni, listen()" << endl;
    }

    int navrat,soket;
    bool prijmonut = false;

    while(true)
    {

        //session pro clienta a bind pro server(+-sokety)
        sshsession = ssh_new();
        if (sshsession == NULL)
            return ESSHNEW;

        //akceptovat pripojeni od klienta
        if (ssh_bind_accept(sshbind, sshsession) != SSH_OK)
        {
            ssh_free(sshsession);
            ssh_bind_free(sshbind);
            return EACCEPT;
        }

        pthread_mutex_lock(&mutexCount); //zavrit mutex
        if (klientPocet < param.maxClient)
            prijmonut = true;
        else
            prijmonut = false;
        pthread_mutex_unlock(&mutexCount); //zavrit mutex

        if (prijmonut)
        {
            SSHARG *arguments = new SSHARG;
            arguments->sshsessionArg = sshsession;
            soket = ssh_get_fd(sshsession);
            arguments->clientAddrArg = ipClientAddress(soket, &navrat);
            arguments->pocetAuth = param.maxAuth;

            if (navrat != EOK)  //klient bude mit smulu, neobslouyi se ho
            {
                delete(arguments);
                printEcode(navrat, param.state);
                ssh_disconnect(sshsession);
                continue;

            }
            if (DEBUG)
            {
                    cout << "sshServer(): pripojil se klient z adresy: " << soket << " " << arguments->clientAddrArg << endl;
            }

            //spustit vlakno
             pthread_t vlakno;

            if (pthread_create(&vlakno, NULL, sshCom, (void *) arguments))
            {
                //vlakno se nevytvorilo, klient nebude obslouzen, bude mu zavre sokent/session
                printEcode(ETHREAD, param.state);
                ssh_disconnect(sshsession);
                delete(arguments);
            }

            pthread_mutex_lock(&mutexCount); //zavrit mutex
            klientPocet++;
            pthread_mutex_unlock(&mutexCount); //zavrit mutex
        }
        else
        {
            printEcode(EMAXCLIENT, SSSH);
            ssh_disconnect(sshsession);
            ssh_free(sshsession);
        }
    }

    ssh_free(sshsession);
    ssh_bind_free(sshbind);
    logFile.close();

    return EOK;
}

int main(int argc, char *argv[])
{
    PARAMS param = getParams(argc, argv);
    int navrat = EOK;

    if (param.ecode != EOK)
    {
        param.state = SHELP;
        printEcode(param.ecode, param.state);
        return EXIT_FAILURE;
    }

    if (param.state == SFTP)
    {
        if ((navrat = netWorkFTP(&param)) != EOK)
        {
            printEcode(navrat, param.state);
            return EXIT_FAILURE;
        }

    }
    else if (param.state == SSSH)
    {
        if ((navrat = sshServer(param)) != EOK)
        {
            printEcode(navrat, param.state);
            return EXIT_FAILURE;
        }
    }


    if (DEBUG)
    {
        cout << "KONEC!!!" << endl;
    }

    return EXIT_SUCCESS;
}
