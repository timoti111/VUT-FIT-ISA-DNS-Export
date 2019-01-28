<h3>Zadanie:</h3>

<tr><td>Vytvořte komunikující aplikaci podle konkrétní vybrané specifikace           
       
pomocí síťové knihovny BSD sockets (pokud není ve variantě zadání            
      
uvedeno jinak). Projekt bude vypracován v jazyce C/C++. Pokud      
individuální zadání nespecifikuje vlastní referenční systém, musí být      
projekt přeložitelný a spustitelný na serveru merlin.fit.vutbr.cz pod operačním systémem Linux.<br><br>Vypracovaný projekt uložený v archívu .tar a se jménem xlogin00.tar odevzdejte elektronicky přes IS. Soubor nekomprimujte.<ul><li><b>Termín odevzdání je 19.11.2018</b> <b>(hard deadline)</b>. Odevzdání e-mailem po uplynutí termínu, dodatečné opravy či doplnění kódu není možné. </li><li>Odevzdaný projekt musí obsahovat:<ol><li>soubor se zdrojovým kódem (dodržujte jména souborů uvedená v konkrétním zadání),</li><li>funkční <i>Makefile </i>pro překlad zdrojového souboru,</li><li>dokumentaci (soubor <i>manual.pdf</i>),            
 která bude obsahovat uvedení do problematiky, návrhu aplikace, popis             
implementace, základní informace o programu, návod na použití. V             
dokumentaci se očekává následující: titulní strana, obsah, logické             
strukturování textu, přehled nastudovaných informací z literatury, popis            
 zajímavějších pasáží implementace, použití vytvořených programů a             
literatura.</li><li>soubor <i>README </i>obsahující krátký textový popis programu s případnými rozšířeními/omezeními, příklad spuštění a seznam odevzdaných souborů,</li><li>další požadované soubory podle konkrétního typu zadání.&nbsp;</li></ol>            
</li><li>Pokud v projektu nestihnete implementovat všechny požadované             
vlastnosti, je nutné veškerá omezení jasně uvést v dokumentaci a v             
souboru README.</li><li>Co není v zadání jednoznačně uvedeno, můžete implementovat podle svého vlastního výběru. Zvolené řešení popište v dokumentaci.</li><li>Při řešení projektu respektujte zvyklosti zavedené v OS unixového typu (jako je například formát textového souboru).</li><li>Vytvořené            
 programy by měly být použitelné a smysluplné, řádně komentované a             
formátované a členěné do funkcí a modulů. Program by měl obsahovat             
nápovědu informující uživatele o činnosti programu a jeho parametrech.             
Případné chyby budou intuitivně popisovány uživateli.</li><li>Aplikace      
nesmí v žádném případě skončit s chybou SEGMENTATION FAULT ani jiným      
násilným systémovým ukončením (např. dělení nulou).</li><li>Pokud            
 přejímáte krátké pasáže zdrojových kódů z různých tutoriálů či             
příkladů z Internetu (ne mezi sebou), tak je nutné vyznačit tyto sekce a            
 jejich autory dle licenčních podmínek, kterými se distribuce daných             
zdrojových kódů řídí. V případě nedodržení bude na projekt nahlíženo             
jako na plagiát.</li><li>Konzultace k projektu podává vyučující, který zadání vypsal.</li><li>Před            
 odevzdáním zkontrolujte, zda jste dodrželi všechna jména souborů             
požadovaná ve společné části zadání i v zadání pro konkrétní projekt.             
Zkontrolujte, zda je projekt přeložitelný.</li></ul><b>Hodnocení projektu</b>:<ul><li><b>Maximální počet bodů za projekt je 20 bodů.</b></li><ul><li>Maximálně 15 bodů za plně funkční aplikace.</li><li>Maximálně 5 bodů za dokumentaci. Dokumentace se hodnotí pouze v případě funkčního kódu. Pokud kód není odevzdán nebo nefunguje podle zadání, dokumentace se nehodnotí.</li></ul><li>Příklad kriterií pro hodnocení projektů:<ul><li>nepřehledný, nekomentovaný zdrojový text: až -7 bodů</li><li>nefunkční či chybějící Makefile: až -4 body</li><li>nekvalitní či chybějící dokumentace: až -5 bodů</li><li>nedodržení formátu vstupu/výstupu či konfigurace: -10 body</li><li>odevzdaný soubor nelze přeložit, spustit a odzkoušet: 0 bodů</li><li>odevzdáno po termínu: 0 bodů</li><li>nedodržení zadání: 0 bodů</li><li>nefunkční kód: 0 bodů</li><li>opsáno: 0 bodů (pro všechny, kdo mají stejný kód), návrh na zahájení disciplinárního řízení. </li></ul>            
</li></ul></td></tr>
<tr><td><b>Variant description:</b></td></tr><tr><td>Cílem projektu je vytvořit aplikaci, která bude umět zpracovávat data protokolu DNS (Domain Name System) a vybrané statistiky exportovat pomocí protokolu Syslog na centrální logovací server.&nbsp;<br><br><b>Spuštění aplikace</b><br><pre>dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]</pre><ul><li>-r : zpracuje daný pcap soubor</li><li>-i : naslouchá na daném síťovém rozhraní a zpracovává DNS provoz</li><li>-s : hostname/ipv4/ipv6 adresa syslog serveru</li><li>-t : doba výpočtu statistik, výchozí hodnota 60s</li></ul><br><b>Upřesnění zadání:</b><br>Aplikace bude vytvářet následující statistiky:<br><br>domain-name rr-type rr-answer count<br><br>Pokud aplikace naslouchá na síťovém rozhraní, jsou statistiky odesílány na syslog server po vypršení definované doby dané přepínačem -t. Při zpracování pcap souboru jsou statistiky odeslány po jeho zpracování. Při obdržení signálu SIGUSR1 vypíše aplikace statistiky na standardní výstup.<br><br>Příklad:<br>google.com A 172.217.23.238 68<br><br><b>Definice syslog zprávy:</b><br>Syslog zprávy budou dodržovat syntaxi dle RFC 5424. Povinné položky je timestamp, hostname, pri, verze, název aplikace a samotná zpráva. Lze doplnit chybějící informace, jako např. PID procesu, aj. Facility je nastaveno na local0 a severity na Informational.<br><br>Příklad Syslog zprávy:<br>&lt;134&gt;1 2018-09-20T22:14:15.003Z 192.0.2.1 dns-export - - - google.com A 172.217.23.238 68<br><br>Limit pro syslog zprávy je typicky 1kB, pro efektivnost můžete sloučit více statistických zpráv do jedné syslog zprávy. V zjednodušené variantě lze posílat každou statistickou informaci jako samostatnou syslog zprávu.<br><br><br><b>Dokumentace:</b><br>Soubor Readme z obecného zadání nahraďte souborem dns-export.1 ve formátu a syntaxi manuálové stránky - viz&nbsp;<a href="https://liw.fi/manpages/">https://liw.fi/manpages/</a>&nbsp;<br>Dokumentaci ve formátu pdf vytvořte dle pokynu v obecném zadání.<br><br><b>Referenční virtuální stroj</b><br>Implementace bude testována na standardní instalaci distribuce CentOS7. Můžete použít image pro CentOS dostupný&nbsp;<a href="http://qwe.fit.vutbr.cz/igregr/centos7.ova">zde</a>&nbsp;(user/user4lab, root/root4lab). Alternativně lze využít server merlin, kde lze otestovat zpracování pcap souboru (pro naslouchání na síťovém rozhraní je třeba root oprávnění).</td></tr>
