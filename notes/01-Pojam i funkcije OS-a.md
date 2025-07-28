# Uvod u operativne sisteme

## Sta je operativni sistem?

Operativni sistem (eng. operating system) je **program(softver)** koji:
-neposredno **rukuje hardverom racunara**
-omogucava **izvrsavanje korisnickih programa** na racunaru 
-sluzi kao **posrednik izmedju korisnickih programa i  racunarskog hardvera** pruzajuci usluge tim programima

Operativni sistem je **sistemski softver**, za razliku od aplikativnog softvera koji se koristi za specificne zadatke. OS omogucava odgovarajuce opste i genericke usluge korisnickim programima, tako da ti korisnicki programi ne pristupaju neposredno hardveru racunara, vec pristup do hardvera obezbedjuje OS.

Operativni sistem je skup rutina koje obavljaju operacije sa hardverskim uredjajima racunara, koje se nalaze u memoriji racunara i koje se mogu koristiti kao usluge. Te usluge korisnicki programi pozivaju kao **sistemske pozive**(engl. system calls). Sistemski pozivi predstavljaju nacin da korisnicki program zahteva neku uslugu OS-a tj mehanizam kojim korisnicki program poziva rutine operativnog sistema; **getc i putc su bibliotecni potprogrami** koje programer koristi u korisnickim programima gotove, oni u svojoj implementacji imaju sistemske pozive kojim zahtevaju usluge(ucitavanje znaka sa tastature/ispis znaka na ekran) od operativnog sistema na kojem se program izvrsava.

**Jednostavni ugradjeni sistemi** (engl. embedded systems) Njima krajnji cilj nije obrada podataka vec, obradu podataka koriste u svrhu upravljanja uredjajima/sistemima. Mogu da rade bez operativnog sistema jer izvrsavaju samo jedan program. Opet lakse je i robusnije da imaju OS on se ovde naziva **bibliotecni OS** (engl. library operating system) u kojem se **rutine** koje implementiraju funkcionalnosti koje su opste i spadaju u odgovornost operativnog sistema, povezuju sa korisnickim kodom kao biblioteke i izvrsavaju se kao jedinstven program (ovakav monolitan softver ucitava u memoriju racunara). Slozeniji ugradjeni sistemi imaju klasican OS.

## Koje su osnovne funkcije OS-a?

1) omogucava pokratanje izvrsavanja, izvrasavanje programa ( jednog ili vise njih uporedo) na hardveru racunara
2) omogucava sto efikasnije uporedo izvrsavanje programa, efikasno koriscenje procesora, memorije i hardverskih resursa
3) fizickih resursa za izvrsavanje programa je ograniceno mnogo, OS se trudi da obezbedi logicki neogranicen kapacicet resursa
4) omogucava obavljanje ulazno-izlaznih operacija pomocu uredjaja koje racunar poseduje
5) komunikacija izmedju programa koji se odvijaju na 1 ili vise udaljenih racunara
6) omogucava programima pristup i operacije nad fajlovima na 1 ili vise udaljenih racunara
7) zastita od nezeljenog uticaja izvrsavanja jednog programa na izvrsavanje drugih programa
8) zastita racunara od malicioznih softvera i drugih neovlascenih pristupa
9) omogucava nacin na koji korisnici racunara sa njim interaguju koriscenjem **korisnickog interfejsa** (engl. user interface)

## Delovi operativnog sistema:

### jezgro (engl. kernel)
-deo operativnog sistema koji je **uvek ucitan** u operativnu memoriju ili se ucitava prilikom ukljucivanja racunara i tu ostaje do njegovog iskljucenja.  
-izvrsava **osnovne** funkcije OS-a  
-pruza usluge programima koji se izvrsavaju na racunaru
### sistemski programi (engl. system program)
-programi koji se **izvrsavaju kao i svi ostali korisnicki programi**, ali od njih se razlikuju jer **se isporucuju kao sastavni deo OS-a**  
-obavljaju **opste radnje** za razliku od korisnickih programa: kopiranje fajlova, pravljenje rezervne kopije...  
-mogu se **pokretati po potrebi, dakle ne zauzimaju stalno memoriju** kao sto je slucaj sa kernelom  
**->** otkaz u jezgru uzrokuje otkaz celog sistema, dok otkaz u sistemskim pozivima ne uzrokuje otkaz sistema  
### korisnicki interfejs (engl. user interface)
-deo OS-a za interakciju sa korisnikom  
-dva tipa UI:  
1) interpreter komandne linije (engl. command line interpreter CLI)  
   -tastatura je ulazni znakovno orijentisan sekvencijalni uredjaj sa kojeg se ucitava znak po znak  
   -monitor je izlazni znakovno orijentisan sekvencijalni uredjaj  
   ->ovaj par uredjaja naziva se **konzola tj terminal**  
   -CLI se zasniva na ciklicnom izrsavanju operacija:  
   1) na ekran ispisuje znak > ili $ kao pokazatelj spremnosti da primi znakove sa ulaza (engl. command prompt)
   2) ucitava znak po znak sa tastature dok ne naidje na enter
   3) uneti niz znakova rasclanjuje na podnizove: komanda i argumenti komande;
   4) izvrsava komandu, opciono komanda ispisuje nesto na ekran
   5) spreman za novu komandu
  ->skup komandi moze se spakovati u **pakete (engl. batch) ili skripte (engl. script)** kako se ne bi morala unositi komanda po komanda  
   -CLI moze biti implementiran u okviru kernela ili kao sistemski program (engl. shell) koji se izvrsava kao svaki drugi program;  
   Ukoliko je implementiran kao sistemski program moze imati vise varijacija:  
   1) kod za obradu komandi se nalazi u samom interpreteru; glavna rutina interpretera ucitava komandnu liniju a potom prelazi na deo koda koji je zaduzen za izvrsavanje te komande. 
   2) interpreter uscitava komandnu liniju, izdvaja komandu i njene argumente, zatim pokrece program koji je dat tom komandom i prosledjuje mu argumente; dakle u ovom drugom slucaju implementacija komandi je izmestena u posebne programe cime se postize da je interpreter krajnje jednostavan.
   3) hibridna verzija interpretera: (npr interpreter MS DOS) INTERNE KOMANDE su implementirane unutar samog interpretera, ukoliko cli ne nadje komandu on je tretira kao EKSTERNU i trazi sistemski program sa tim nazivom
3) graficki korisnicki interfejs (engl. graphical user interface GUI)
   -intuitivan  
   -ekran je rasterski izlazni uredjaj za prikaz matrice pixela u boji  
   -od ulaznih uredjaja koriste se tatstaura, mis, olovka, touch screen  
   -nudi desktop apstrakciju radne povrsine, slicice (vizuelni prikaz)  
   -korisnik zadaje komande intuitivnim akcijama nad objektima, prisutan je polimorfisam jer se iste akcije nad razlicitim tipom objekata razlicito ispoljavaju  













