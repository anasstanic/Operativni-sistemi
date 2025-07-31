## SISTEMSKI POZIV (engl. system call)

-je metod kojim **program koji se izvrsava** na OS-u **trazi odredjenu uslugu** od OS-a  
-kada se program pise na vise programskom jeziku poput C/C++, njihov program se prevodi u binaran, masinski kod i takvi se izvrsavaju na racunaru. Kada se program pise na ovako nekom visem programskom jeziku sistemski pozivi se izvrsavaju potprogramima is standardnih, sistemskih biblioteka, tj sistemski poziv se u izvornom kodu vidi kao obicna C funkcija implementirana u okviru neke biblioteke.  
-bibliotecke funkcije npr **getc, exit** u sebi sadrze sistemske pozive  
-bibliotecka funkcija **strchr** u sebi ne sadrzi sistemske pozive jer njena implementacija NE zahteva nikakve usluge OS-a  
-slozena bibliotecka funkcija **printf** analizira format dat prvim argumentom, konvertuje vrednosti ostalih argumenata u nizove znakova, potom vrsi visestruke sistemske pozive putc koji ispisuju znak po znak  
**programski interfejs za apliakcije (engl. API application programming interface)** datog OS-a na konkretnom progrmskom jeziku je skup dostupnih biblioteckih potprograma koji izvrsavaju sistemske pozive na nekom OS-u. Implementacija ovih potprograma unutar biblioteka sadrzi procesorske instrukcije koje vrse sistemski poziv na masinskom, binarnom nivou izveden na nacin na koji to OS zahteva. Ovo naravno moze izazvati **suspenziju** odlaaganje zaustavljanje izvrsavanja programa dok se neka usluga ne izvrsi.  
**interfejs sistemskih poziva tj binarni interfejs za aplikacije (engl. ABI application binary interface)** implementacija potprograma na binarnom nivou  

**programski interfejsi za sistemske pozive**
-libc - standardna biblioteka jezika C/C++  
      - sadrzi razne funkcije ali i funkcije koje u sebi sadrze sistemske pozive  
      - funkcije iz zaglavlja **stdio.h stdlib.h thread.h** u sebi sadrze sistemske pozive koje implementiraju svi OS-i na kojima se mogu izvrsavati standardni programi a ovim jezicima  
-POSIX- engl. Portable operating system interface based on Unix   
      - standardni API, ima za cilj da omoguci da svi programi koji koriste ovaj API budu prenosivi na sve sisteme nalik Unix-u: Linux, MAC OS X, Solaris, AIX... (engl. Unix like systems)  
-Windows API- je API za Windows sistem razlicitih generacija i verzija  


## PROCES
-je jedno izvrsenje programa na datom racunaru i pod kontrolom njegovog OS-a, koje potencijalno tece uporedo sa drugim takvim izvrsavanjima istog ili drugih programa.  
- proces!=program  
  Program je staticki zapis tj specifikacija onoga sta racunar treba da uradi.  
  Jedna aktivacija programa je proces, svako od tih izvrsavanja radi nad svojim podacima.  
### Podela racunarskih sistema u odnosu na to koje programe moze izvrsavati  
  Monoprogramski racunarski sistem  
    sistem koji izvrsava samo jedan program koji mu se zada, ne bilo koji; npr ugradjeni programi ves masina..  
  Multiprogramski racunarski sistem  
    sistem kojem mogu da se zadaju razliciti proizvoljni programi pisani za taj sistem  
    
### Podela OS po tome koliko procesa moze da izvrsava uporedo:
    Monoprocesni  
      u 1 trenutku moze da se izvrsava samo 1 program; naredni program moze da se pokrene tek kada se zavrsi program koji se trenutno izvrsava  
    Multiprocesni  
      omogucava uporedo izvrsavanje vise procesa  
  ->svi sadasnji uredjaji su multiprogramski sa multiprocesorskim OSom  

## MULTIPROGRAMIRANJE
-prvi racunari su bili monoprocesni  
**su imali paketne sisteme**
-ulazni uredjaj je bio citac busenih kartica (engl. punched card reader)  
      nije bio povezan sa racunarom  
      tekst programa ili podaci su se unosili tastaturom u busac kartica koji je sluzio za binarno kodovanje unete znakove busenjem kartica  
      za 1 uneti red busac kartica je pravio 1 karticu  
      spil izbusenih kartica za 1 program i njegove ulazne podatke ILI za paket vise takvih programa se ubacivao u **citac busenih kartica**; ovaj uredjaj je pomocu svetlosti i rupica od binarnog zapisa stvarao elektronski zapis i ucitavao u racunar  
-izlazni uredjaj je bio linijski stampac (engl. line printer)  
      stampao je sekvencijalno znak po znak redom kojim ih racunar salje na taj uredjaj  
      imao je valjak neprekidne trake na koji je ispisivao izlaz
      tackicama je iscrtavao znak, matrica 8x8
      CR (engl. carriage return) vraca glavu na pocetak reda
      LF (engl. line feed) daje komandu da valjak pomeri papir za jedan red dalje kako bi se preslo u novi red
-kasnije su uvedene magnetne trake (engl. magnetic tape) za snimanje ili ucitavanje programa i podataka, pri cemu je pristup snimljenom sadrzaju sekvencijalan, po redosledu odredjenom kretanjem trake.
-postupak:  
      termin posao (engl. job) je tada znacavao napisani program sa svojim ulaznim podacima. Taj posao, podnet na izvrsavanje, se smestao na ulazni uredjaj(citac kartica kasnije magnetna traka) i cekao da bude pokrenut. OS (tada je imao naziv monitor) je imao zadatak da sa ulaznog uredjaja u memoriju ucita posao koji je sledeci na redu i pokrene njegovo izvrsavanje. U operativnoj memeoriji se nalaze samo OS i taj posao koji se trenutno izvrsava. OS je trebao da obezbedi ulazno-izlazne operacije: ucitavanje i ispis podataka ovo se izvrsavalo sekvencijalno.  
      ponasanje ovakvog programa moze se opisati kao **ciklicno tj naizmenicno smenjivanje 2 faze**  
      1)nalet izvrsavanja na procesoru (engl. CPU burst) izvrsavanje sekvence susednih procesorskih instrukcija koje rade samo sa podacima iz registara procesora ili operativne memorije  
      ne koriste usluge OS-a tj ne koriste ulazno izlazne operacije  
      2)ulazno-izlazna operacija (engl. I/O operation) pokrece se kada proces **trazi sistemsku uslugu npr ucitavanje ulaznih podataka ili ispis svojih rezultata**  
      
      |||||||                    |||                 |||||  
      |<-CPU burst  
       <-I/O operation  
      dakle iz ovoga vidimo da je slaba iskoriscenost procesora, jer dok se obavlja I/O operacija proces mora da ceka
      
      

