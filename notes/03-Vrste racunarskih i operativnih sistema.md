# Vrste racunarskih i operativnih sistema

## Multiprocesorski i distribuirani sistemi
  Postoje 2 osnovne paradigme hardverske arhitekture racunarskih sistema koji omogucavaju izvrsavanje programa na vise procesora:
  **1) Multiprocesorski sistem:**  
     -racunarski sistem sa vise procesora koji dele zajednicku OM (engl. shared memory)- takva je vecina danasnjih racunara  
     -procesori mogu pristupati toj deljenoj memoriji, u nju smestati podatke i citati iz nje, preko zajednicke magistrale na koju su svi povezani
     -procesorsko jezgro i procesorske niti su hardverski elementi unutar procesora i omogucavaju uporedo izvrsavanje instrukcija vise procesa  
     **-Podela multiprocesorskih sistema (hardverski gledano):**    
       -simetrican sistem: svi procesori su opste namene, jednaki su i imaju isto vreme pristupa OM  
       -asimetrican sistem: neki procesori su specijalizovani za posebne namene (za graficke, za aritmeticke operacije) ili imaju razlicito vreme pristupa OM  
     **-Podela OS-ma za multiprocesorske racunare:**    
       -simetrican:sve procesore tretira na isti nacin, svi oni **mogu izvrsavati kod procesa i kod kernela**  
       -asimetrican:1 procesor je gazada(engl. master) i on rasporedjuje procese na druge procesore i izvrsava kod kernelea za ostale sistemske usluge; Ostali procesori su robovi i izvrsavaju samo kod korisnickih procesa koje im master dodeli  
     -OS DODATNO MORA DA RASPOREDJUJE PROCESE NA PROCESORE kako bi ih efikasno koristio  
     -dobro je (ali nije neophodno) da se proces izvrsava na procesoru za koji ima afinitet (da bi se smanjio promasaj u kes memoriji prilikom promene procesora na kojem se izvrsava proces)  
  **2) Distribuiran sistem:**  
     -sistem sa vise procesora koji **NEMAJU** zajednicku OM, vec **svaki procesor ima svoju OM**  
     -procesori su povezani **komunikacionom mrezom** preko koje mogu razmenjivati poruke  
     **-Distribuirani sistemi danas ukljucuju sledece konfiguracije:**  
       -specijalizovani racunar sa vise procesora i brzom interkonekcionom mrezom izmedju njih  
       -lokalna racunarska mreza (engl. local area network LAN): racunarska mreza sa vise povezanih racunara na relativno malom prostoru i ogranicenog je pristupa  
       -mreza sireg podrucja (engl. wide area network WAN): regionalna ili geografski distribuirana mreza  
       -Internet  
     -Udaljeni pristup podrazumeva pristup jednom racunaru(server) preko drugog udaljenog racunara (klijent) tako sto klijent razmenjuje poruke sa serverom preko racunarske mreze. Korisnik pristupa svom racunaru preko svog korisnickog interfejsa, dok sa OS-om servera komunicira na jedan od **nacina:**  
     -Nacini na koje klijent interaguje sa OS-om racunara servera:  
       -**SSH protokol**;sigurna skoljka (engl. secure shell): ovo je protokol za **kriptovanu** komunikaciju sa serverom  
         na klijentskom racunaru se izvrsava proces koji predstavlja skoljku sa interpreterom komandne linije, ali taj interpreter pristupa serverskom racunaru i stvara utisak neporedsnog rada na konzoli serverskog racunara  
       -pomocu **udaljenje radne povrsine** (engl. remote desktop): omogucava izvrsavanje skoljke sa grafickim korisnickim interfejsom na klijentskom racunaru koja pristupa udaljenom serveru i stvara utisak neporednog rada na to serverskom guiju.  
    **DISTRIBUIRANI OS** (engl. distributed operating system): sakriva postojanje vise fizickih racunara;  
    to je OS koji na klasteru (skupu umrezenih racunara) stvara utisak jedinstvenog logickog prostora racunarskih resursa i sakriva postojanje razlicitih fizickih racunara.  
    rasporedjuje procese na procesore umrezenih racunara, fajlove rasporedjuje po uredjajima na tim racunarima i stvara privid da su svi ti fajlovi dostupni na isti nacin  
     
## Personalni racunari
(engl. personal computer, PC)  
Racunar za licnu upotrebu, stoni racunar, prenosivi laptop, tablet, pametni telefon...  
OS na prvi PC su bili monoprocesni, sada su multiprocesni  
Danas su procesori na PC slabo iskorisceni ali to apsolutno nije problem, jer su siroko dostupni i jeftini i racunari i procesori  
Danas su prioriteti: efikasnost izvrsavanja vise aplikacija istovremeno, lakoca i pogodnost upotrebe, mogucnost umrezvanja, pristup Internetu, pristup udaljenih fajlovima, povezivanje sa prikljucenim uredjajima, zastita privatnosti i podataka, sto manja potrosnja energije (baterije)...  


## Serverski sistemi  
Racunar namenjen za opsluzivanje zahteva koji stizu komunikacionim protokolima preko racunarske mreze sa velikog broja udaljenih klijent racunara  
Da bi uspesno opsluzivao sve te zahteve racunar server ima velike hardverske kapacitete:  
-ima vise procesora OPSTE namene 8,16 i vise kao i odgovarajuce koprocesore  
-ima veliku OM 128GB, 256GB, 512GB ili 1TB  
-vise diskova na posebnim uredjajima, skladistima velikog ukupnog kapaciteta  
-mreznu vezu visoke propusnosti  

## Sistemi u oblaku  
-su distribuirani sistemi sa mnogo povezanih serverskih racunara u 1 racunarskom centru (engl. data center) ili u regionalno ili globalno rasporedjenim racunarskim centrima koji obezbedjuju razlicite usluge korisnicima-one su dostupne putem Interneta a o celoj infrastrukturi brine pruzalac usluge.  
-Sistemima u oblaku upravljaju specificni distribuirani operativni sistemi...  

## Ugradjeni sistemi i sistemi za rad u realnom vremenu  
- ugradjen (engl. embedded) sistem je sistem koji sluzi za nadzor i upravljanje hardverskog okruzenja i ispunjava svoj cilj obradom informacija. Obrada informacija je sredstvo ali ne i krajnji cilj ovih sistema.
- **Sistemi za rad u realnom vremenu** (engl. real time RT system): tacan rezultat dobijen za duze vreme je jednako los kao i netacan rezultat
   **podela RT sistema**  
    1. tvrdi: postoji (engl. deadline) aplsoitni odziv za rezultat, jer kasnjenje moze dovesti do velikih katastrofa i ugrozavanja ljudskih zivota; koriste se posebni RT OS  
    2. meki: vremenski rokovi su vazni i treba da se postuju ali se povremeno mogu i prekoraciti sve dok performanse sistema (kasnjenje i propusnost) ulazi u zadate okvire. npr. telefonske centralne, uredjaji za kablovsku tv..

