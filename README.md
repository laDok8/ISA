# Hodnocení projektu:
18/20

    Maximální počet bodů za projekt je 20 bodů.
        Maximálně 15 bodů za plně funkční aplikaci.
        Maximálně 5 bodů za dokumentaci. Dokumentace se hodnotí pouze v případě funkčního kódu. Pokud kód není odevzdán nebo nefunguje podle zadání, dokumentace se nehodnotí.

# zadani 

Vytvořte klient/server aplikaci, která umožní přenést soubor skrz skrytý kanál, kde data jsou přenášena uvnitř ICMP Echo-Request/Response zpráv. Soubor musí být před přenosem zašifrován, aby nebyl přenášen v textové podobě.

Spuštění aplikace:
```
secret -r <file> -s <ip|hostname> [-l]

    -r <file> : specifikace souboru pro přenos
    -s <ip|hostname> : ip adresa/hostname na kterou se má soubor zaslat
    -l : pokud je program spuštěn s tímto parametrem, jedná se o server, který naslouchá příchozím ICMP zprávám a ukládá soubor do stejného adresáře, kde byl spuštěn.
```

Upřesnění zadání:
Program zpracuje vstupní argumenty, načte soubor, zašifruje ho a zašle skrz ICMP zprávy na zvolenou IP adresu, kde program, spuštěný v listen (-l) módu, tyto zprávy zachytí, dešifruje a soubor uloží na disk.

    Program může používat pouze ICMP zprávy Echo-request/reply.
    Pro správné chování bude třeba definovat protokol pro přenos dat. (např. je třeba zaslat jméno souboru, ověřit, že soubor byl přenesen celý, apod.) Tento protokol je na vašem uvážení a definujte ho v rámci dokumentace.
    Jako šifru použijte AES, dostupnou např. pomocí knihovny openssl [1]. Jako klíč použijte svůj login.
    Program se musí vypořádat se souborem větší, jak max. velikost paketu na standardní síti (1500B), tj. musí být schopen větší soubor rozdělit na více paketů.
    Můžete uvažovat, že v rámci přenosu nedojde ke ztrátám paketů. Pokud implementujete formu spolehlivého přenosu, uveďte to v dokumentaci.
    Při vytváření programu je povoleno použít hlavičkové soubory pro práci se sokety a další obvyklé funkce používané v síťovém prostředí (jako je netinet/*, sys/*, arpa/* apod.), knihovny pro práci s vlákny (pthread), pakety (pcap), signály, časem, stejně jako standardní knihovnu jazyka C (varianty ISO/ANSI i POSIX), C++ a STL a knihovnu SSL. Další knihovny nejsou povoleny.

[1] https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
