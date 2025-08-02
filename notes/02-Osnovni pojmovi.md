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
   
### Podela racunarskih sistema u odnosu na to koje programe moze izvrsavati:
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
### Prvi racunari su bili monoprocesni  
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
      
     P1:|||||||                    |||                 |||||  
      |<-CPU burst  
       <-I/O operation  
      dakle iz ovoga vidimo da je slaba iskoriscenost procesora, jer dok se obavlja I/O operacija proces mora da ceka, ovolika kolicina neiskoriscenosti je neprihvatljiva

### Resenje ovog problema: MULTIPROCESNI SISTEMI
-u OM treba ucitati vise procesa i izvrsavati ih uporedo: dok jedan proces ceka na zavrsetak I/O operacija, CPU(procesor) moze da izvrsava instrukcije nekog drugog procesa koji je ucitan u OM => sistem postaje MULTIPROCESNI. Ovim smo dobili da se CPU vremenski multipleksira izmedju razlicitih procesa: ovo se naziva MULTIPROGRAMIRANJE (CPU u jednom momentu izvrsava instrukcije jednog procesa a u drugom trenutku izvrsava instrukcije drugog procesa...)  
-Kada jedan proces zatrazi I/O operaciju=>OS obezbedjuje da CPU predje na izvrsavanje nekog drugog procesa.  
-glavni dakle uslov za sprovodjenje ovog vida resenja jeste:  
1) procesor moze da izvrsava samo one instrukcije koje se nalaze u OM, dakle u memoriji mora biti ucitano vise PROCESA
Upravo zbog ovog uslova uvodi se korisceje **magnetnih diskova** umesto mag traka. Magnetni diskovi omogucavaju da OS moze pristupiti podacima sa diska direktno i u proizvoljnom redosledu bez obzira na to gde su ti podaci smesteni. Magnetni disk je blokovski orijentisan I/O uredjaj, podaci se mogu upisivati na disk i kupiti sa diska, podaci se prenose iskljucivo u blokovima velicine po 512B=> OS sada odlucuje koje ce procese izvrsavati na osnovu zauzeca CPU i OM, NE samo na osnovu redosleda kojim su poslovi podneti.  
-CPU je ovim mnogo bolje iskoriscen; stepen iskoriscenosti CPU raste sa porastom stepena multiprogramiranja  
-ukupna **propusnost sistema** tj kolicina obavljenih procesa u jedinici vremena je sada mnogo veca nego za monoprocesni sistem  
### Nove odgvornosti multiprocesnog OS-a:  
-**Rasporedjivanje poslova (engl. job scheduling):**  
            OS bira koje procese ce pokrenuti iz skupa poslova podnetih za izvrsavanje (engl. submitted); ovo danas NIJE U IMPLEMENTACIJI
            
-**Promena konteksta (engl. context switch):**  
            OS obezbedjuje da se procesor sa izvrsavanja jednog procesa prebaci na izvrsavanje drugog, ali tako da moze da se lepo prebaci na ponovno izvrsavanje prethodnog procesa kao da nije bio prekinut  
            
-**Rasporedjivanje procesa na procesoru (engl. process/processor scheduling):**  
            OS bira koji proces ce dobiti CPU iz skupa procesa koji mogu da nastave izvrsavanje  
            
-**Preotimanje procesora (engl. preemption):**  
            Treba zastititi sistem od situacije u kojoj neki proces nikada ne izvrsi sistemski poziv, preotme mu se procesor i problem je resen  
            
-**Problem adresiranja memorije:**    
            Omoguciti da svaki proces **adresira svoje insturukcije i podatke u OM** bez obzira na to sto se ne zna na kojoj adresi ce biti smestene instrukcije procesa prilikom ucitavanja u memoriju  
            
-**Upravljanje memorijom (engl. memory management)**:  
            OS mora smestiti procese u OM, rukovati slobodnim i zauzetim delovima memorije  
            
-**Rasporedjivanje operacija na uredjajima (engl.device scheduling)**:  
            OS opsluzuje zahteve za prekid za koriscenje i/o uredjaja na neki specifican nacin  
            
-**Zastita (engl. protection):**  
            Zastititi delove memorije koji pripadaju kernelu i procesima od uticaja drugih porcesa ili lose namere  

### KONZOLA I STANDARDNI ULAZ/IZLAZ
Mainframe racunari pojavljuju se 1070. i koriste se do 90ih.
Sastojali su se od CPU, OM, I/O uredjaja (diskovi, stampaci magnetne trake..) + terminal tj konzola. Upravo ovo ih izdvaja od dosadasnjih racunara (pre 1970)  
Konzola se sastojala iz monitora i tastature. Tastatura je ulazni uredjaj principijelno isti danasnjoj verziji. Monitori su sekvencijalni izlazni uredjaji, ponasa se isto kao i linijski stampac.  
Na svakoj konzoli (terminalu) moze da radi jedan korisnik koji se prethodno logovao (engl. log in) pomocu korisnickog imena i lozinke; potom zadaje komande pomocu interpretera komandne linije (engl. CLI)  
Komande koje se zadaju na konzoli mogu biti sistemske (ispis sadrzaja tekuceg direktorijuma) ili pokretanje nekog procesa  
OS izvrsava po jedan proces nad istim programom tj nad interpreterom komandne linije (CLI), po jedan proces za svaki terminal tj za svakog prijavljenog korisnika. Ovaj proces koristi konzolu i kao ulazni (sa nje cita znakove koje interpretira kao komandu sa argumentima) i kao izlazni uredjaj(ispis efekata komande)  

#### MEHANIZMI U OPERATIVNIM SISTEMIMA
Kada komanda zahteva pokretanje novog procesa nad nekim programom, interpreter komandne linije (CLI) kao roditeljski (engl. parent) proces stvara novi dete (engl. child) proces nad zadatim programom. CLI se kao proces roditelj suspenduje tj zustavlja izvrsavanje dok se pokrenuti dete proces ne zavrsi, tj dok pokrenuti proces dete ili zahtevana komanda ne zavrsi svoje izvrsavanje i ne vrati kontrolu roditeljskom procesu
1) Rukovanje procesima decom i konzolama
   OS treba da rukuje mnostvom konzola i procesa koji izvrsavaju isti program CLI, tako da svaki porces od tih procesa moze da koristi bas svoju konzolu kao ulazno izlazni uredjaj. OS uvodi **standardni ulaz i standardni izlaz** koji je pridruzen svakom procesu. Da bi proces dete mogao biti interaktivan tj da prima i ispisuje znake na istu konzolu sa koje je i pokrenut, nasledjuje standardni ulaz i izlaz od svog roditelja.  

2) Mehanizam prenosa argumenata komandne linije do procesa deteta  
   Proces dete ove argumente dobija sistemskim pozivom.  
   U C jeziku ovi argumenti se vide kao argumenti funkcije main (argc i argv)  
   Programi koji ovako interaguju sa korisnicima se nazivaju konzolni programi ili aplikacije (engl. console application)
3) echo  
   Odziv racunara pri koriscenju interpretera komandi preko terminala je vazan. Racunar mora na nekakvu akciju korisnika (enter na primer) da da neki signal da je tu komandu prihvatio. Ovaj odziv treba da bude brz. Ovo nije efekat hardverske veze monitora i tastature, vec CLI mora da ucita znak sa tastature sistemskim pozivom, da obradi taj znak i ukoliko treba da ga ispise na ekran takodje sistemskim pozivom
### PREOTIMANJE I RASPODELA VREMENA

     Izvrsavanje 2 interaktivna procesa BEZ preotimanja:  
      P1: ||||||||||||||||////////  
      P2: ///.............||||////  
             ^                ^tu se tek desila reakcija sistema(ispis)
             tu se desila akcija korisnika(taster)
       Vreme odziva:        ... i ||| do ^
       CPU nalet:           |||
       Cekanje na akciju:   ///
      ->Vidimo da je vreme odziva predugo sto dovodi do neudobnosti u radu korisnika. Zasto? Zato sto dok procesor izvrsava neki proces, on ze       to raditi sve dok ne zavrsi taj zapoceti CPU nalet, ukoliko se pre zavrsetka tog CPU naleta desi akcija korisnika za neki drugi proces,       promena konteksta se nece desiti sve dok se CPU nalet prvopokrenutog procesa ne zavrsi, pa ukoliko taj nalet duze traje korisnik ce duze       i cekati reakciju sistema.

---
     Izvrsavanje 2 interaktivna procesa SA preotimanjem:
      Ovo se naziva: **MEHANIZAM PREKIDA** (engl. interrput): PREKIDA SE TEKUCE IZVRSAVANJE I PRELAZI SE NA KOD KERNELA   
      Ovo se naizva i: **PREOTIMANJE PROCESORA**
      P1: |||PREOTIMANJE|||||||||//  
      P2: /// ||||/////////////////  
                 ^            
                 tu se desila akcija korisnika(taster) I ubrzo je preotimanjem sistem brzo reagovao sto je dovelo do KRACEG VREMENA ODZIVA!!!
       Vreme odziva:        ...
       CPU nalet:           |||
       Cekanje na akciju:   ///
      Ovo se postize tako sto **kernel** vrsi promenu konteksta i preusmeri procesor na ivrsenje procesa koji treba da isporuci odziv i koji je iz tog razloga hitniji za samo izvrsavanje.



      
            
            
            

      


      
      
      

