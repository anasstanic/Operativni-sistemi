## SISTEMSKI POZIV (engl. system call)

-je metod kojim **program koji se izvrsava** na OS-u **trazi odredjenu uslugu** od OS-a
-kada se program pise na vise programskom jeziku poput C/C++ sistemski posivi se izvrsavaju potprogramima is standardnih sistemskih biblioteka.
-bibliotecke funkcije npr **getc, exit** u sebi sadrze sistemske pozive
-bibliotecka funkcija **strchr** u sebi ne sadrzi sistemske pozive jer njena implementacija NE zahteva nikakve usluge OS-a
-slozena bibliotecka funkcija **printf** analizira format dat prvim argumentom, konvertuje vrednosti ostalih argumenata u nizove znakova, potom vrsi visestruke sistemske pozive putc koji ispisuju znak po znak
**programski interfejs za apliakcije (engl. API application programming interface)** je skup dostupnih biblioteckih potprograma koji izvrsavaju sistemske pozive
**interfejs sistemskih poziva tj binarni interfejs za aplikacije** kasnije...

**programski interfejsi za sistemske pozive**
-libc - standardna biblioteka jezika C/C++ 
      - sadrzi razne funkcije ali i funkcije koje u sebi sadrze sistemske pozive 
      - funkcije iz zaglavlja stdio.h stdlib.h thread.h u sebi sadrze sistemske pozive koje implementiraju OSi na kojima se mogu izvrsavati standardni programi a ovim jezicima
-POSIX- engl. Portable operating system interface based on Unix 
      - standardni API, ima za cilj da omoguci da svi programi koji koriste ovaj API budu prenosivi na sve sisteme nalik Unix-u (engl. Unix like systems)
-Windows API- je API za Windows sistem razlicitih generacija i verzija


## PROCES
-je jedno izvrsenje programa na datom racunaru i pod kontrolom njegovog OS-a, koje potencijalno tece uporedo sa drugim takvim izvrsavanjima istog ili drugih programa.
- proces!=program
  Program je staticki zapis tj specifikacija onoga sta racunar treba da uradi.
  Jedna aktivacija programa je proces, svako od tih izvrsavanja radi nad svojim podacima.
-Podela racunarskih sistema u odnosu na to koje programe moze izvrsavati
  Monoprogramski racunarski sistem:
    izvrsava jedan predefinisani program, npr ugradjeni programi ves masina..
  Multiprogramski racunarski sistem:
    sistem kojem mogu da se zadaju razliciti programi pisani za taj sistem
  -Podela OS po tome koliko procesa moze da izvrsava uporedo:
    Monoprocesni
      naredni program moze da se pokrene tek kada se zavrsi program koji se trenutno izvrsava
    Multiprocesni
      omogucava uporedo izvrsavanje vise procesa
  ->svi sadasnji uredjaji su multiprogramski sa multiprocesorskim OSom

## MULTIPROGRAMIRANJE
-prvi racunari su imali paketne sisteme i bili su monoprocesni
-ulazni uredjaj je bio citac busenih kartica (engl. punched card reader)
-izlazni uredjaj je bio linijski stampac (engl. line printer)
-kasnije su uvedene magnetne trake (engl. magnetic tape) za snimanje ili ucitavanje programa i podataka, pri cemu je pristup sekvencijalan i dalje po redosledu odredjenom kretanjem trake.


