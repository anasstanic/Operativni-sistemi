# UPRAVLJANJE MEMORIJOM  
## ADRESIRANJE MEMORIJE  

### ARHITEKTURA PROCESORA  
Procesor (engl. processor CPU) je centralni hardverski deo svakog racunara, jer on izvrsava program i tako obradjuje informacije.  
**Arhitekturu procesora** cine njegov interfejs tj elementi koji su vidljivi softveru, u te elemente spada: skup instrukcija, skup programski dostupnih registara, skup podrzanih nacina adresiranja...  
**INSTRUKCIJA**   
-je binarni zapis, ima svoju velicinu, definise zadatak tj operaciju za procesor: citanje operanada (citanje vrednosti dostupnih procesorskih registara i/ili lokacija operativne memorije), upis rezultata u programski dostupne registre i/ili lokacije operativne memorije, ar ili log operacije nad operandima, odredjivanje mesta sledece instrukcije...  
-nazivamo ih **masinske instrukcije**, **masinski jezik** je nacin zapisivanja masinskih instrukcija bianrnimm kodom  
-arhitekura procesora definise format binarnog zapisa instrukcija  
**FORMAT INSTRUKCIJE NA PROCESORU picoRISC**  
31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00  
.......OP CODE......... AddrMode ......R0...... ......R1...... ......R2...... ..Type.. ne koriste se  
        8b                 3b           5b            5b             5b          3b              
R0,R1,R2 su programski dostupni registri, R0 je odredisni; R1 i R2 su izvorisni  
**Simbolicki masinski jezik tj asembler:**  
  masinska instrukcija napisana tako da je ekvivalentna binarnoj verziji, ali je simbolicka tj citljiva coveku programeru  
  dakle: jedna ova instrukcija (simbolicka tj asemblerska) odgovara jednoj masinskoj instrukciji
  add r0,r1,r2 ZNACI r0=r1+r2; i mozemo ga prevesti u binarni kod  
**Nacin adresiranja** je specifikacija kako se odredjuje mesto operanda (registar ili lokacija u memoriji) tj resultata instrukcije ili adresa lokacije u memoriji na kojoj se nalazi sl instrukcija  
**Programski dostupni registri** su registri procesora u koje instrukcija upisuje vrednosti ili iz kojih instrukcija cita vrednosti. Nema nepredvidivih akcija nad programski dostupnim registrima, to je neohodno za pravilan rad celokupnog sistema, kako on ne bi dosao u nekonzistentno stanje.  
  **Podela programski dostupnih registara:**  
  1. **REGISTRI POSEBNE NAMENE**  
   njihova namena je unapred definisana  
   najcesce se ne referenciraju eksplicitno u insturkciji, odredjene instrukcije implicitno(indirektno) podrazumevaju njihovo koriscenje u svojoj semantici; to je ono kao recimo jmp pa znas da ce da se incrementira pc, neces pisati pc++(VALJDA)  
   PC, PSW, SP  
  2. **REGISTRI OPSTE NAMENE**  
     za cuvanje vrednosti koje se tumace kao podaci(operandi, rez operacija) ili adrese lokacija memorije u kojima se nalaze opet podaci ili instrukcije programa    
   
**Interni registri** procesor poseduje i njih, oni se koriste za implementaciju i nisu dostupni u instrukcijama. DAKLE instukicija ne moze da upisuje u njih ili cita njihove vrednosti. Oni **nisu deo arhitekture procesora** i potpuno su nevidljivi softveru.  

**Podela(PODELA PO STRUKTURI-KONCEPCIJA) procesora na CISC i RISC**  
  **CISC-Complex Instruction Set Computer**   
    -procesori imaju slozenu arhitekturu    
    -procesori uvode ogranicenja, pravila koriscenja registara opste namene...  
    -registri opste namene se dele na registre za podatke i registre za adrese  
  **RISC-Reduces Instruction Set Computer**  
    -procesori imaju jednostavnu, pravilnu, ortogonalnu arhitekturu  
    -nema ogranicenja u koriscenju registara opste namene (svi se mogu koristiti i za adrese i za podatke)  
    -svi registri se mogu koristiti u svim nacinima adresiranja  
    -najcesce imaju **load/store arhitekturu** sto znaci da ostale instrukcije rade sa vrednostima iz programski dostupnih registara  
    -**registarski fajl** skup registara opste namene; registri se oznacavaju generickim oznakama R0,R1,R2...  
    -zbog manjka ogranicenja, olaksane su interne tehnike poput **protocne obrade i superskalarnosti**  
    -**staza za podatke(engl. data path)** RISC procesori u svojoj **internoj implementaciji** imaju stazu za podatke  
    -**ALU Aritmetic-Logic Unit** je kombinaciona ili sekvencijalna mreza koja izvrsava ar ili log operaciju, rezultat operacije postavlja na svoje izlazne linije. Izlazni signali ALU-a su vezani na ulaze registara opste namene. malo preskoceno objasnjenje rada...  
**picoRISC je procesor load/store arhitekture sa registarskim fajlom od 16 registara opste namene**  
**klasicna FON NOJMANOVA arhitektura procesora:**    
  procesor dohvata instrukcije iz OM i izvrsava ih jednu po jednu, uvecava se brojac PC (za velicinu dohvacene instrukcije)-njegovaq vrednost sekoristi kao adresa mem lokacije na kojoj se nalazi naredna instrukcija ili njen deo. Kod instukcije skoka, nova instrukcija definise vrednost PC-a. **Slika 4.3 strana 50, 51, 52-53 objasnjenje**  
  **magistrala (engl. bus)** nalazi se izmedju procesora i operativne memorije: skup linija koje prenose signale  
    1. data bus-magistrala podataka  
      njene vrednosti definisu podatak koji se cita ili upisuje u memoriju  
    2. adress bus-adresna magistrala  
      njene vrednosti definisu lokaciju memorije sa kojom se vrsi zadata operacija  
    3. control signals-upravljacke linije  
      definisu da li se radi o load ili store operaciji  
  **PSW (engl. program status word)** specijalizovani programski dostupan registar procesora, neki njegovi biti se postavljaju implicitno kao posledica rezultata i sluze kao indikatori statusa izvrsene operacije ili njenog rezultata. Negde se naziva i **flag registar registar zastavica**    
  Z-Zero flag: rez op je 0  
  C-Carry flag: doslo do prenosa ili pozajmice u ar op  
  N-Negative flag: rez ar op je neg  
  V-oVerflow flag: doslo do prekoracenja u ar op  
  -instrukcije uslovnog skoka mogu koristiti proveru ovih flegova pa u zavisnosti od tih vr da se vrsi/ne vrsi skok   
  -cmp poredi 2 vrednosti i: u Z stavlja 1 ako je rez oduzimanja 0, ili na 1 u suprotnom  
  -jnz (jne) skace ukoliko je Z=1 (ja mislim da je ovo greska to valjda vazi za jz?)  
  **picoRISC NE POSEDUJE psw**:  sub r3, r1, r2  
                                 jnz r3, 0xA1  //skoci na A1 ako nije 0 u r3  
**Skupovi instrukcija**  
1. **ARITMETICKO LOGICKE**  
   add,subtract,compare,multiply,divide,and,or,xor  
   mogu raditi samo sa operandima iz registara opste namene  
2. **INSTRUKCIJE PRENOSA PODATAKA**  
   load-iz mem u reg, store-iz reg u mem, move-prepisivanje sa jednog na drugo mesto  
3. **INSTRUKCIJE SKOKOVA**
   u registar PC smestaju vrednost adrese naredne instrukcije na koju se skace ukoliko je uslov ispunjen, implicitno se uvek izvrsava instrukcija iza tekuce (ukoliko ne dolazi do vanrednosg skoka)
   vrste skokova:
     uslovni: najcesce je uslov indikator iz PSW ili nekog registra zadatog u instrukciji
     bezuslovni: jmp 0xff12456

### OPERATIVNA MEMORIJA        
-je linearno uredjen skup celija tj lokacija sa pridruzenim adresama(celim brojevima) iz skupa od 0 do 2^n-1        
-n-sirina adrese u b, tj sirina adresne magistrale, najcesce 32b ili 64b, negde postojalo 16,20...        
-svaka celija cuva binarni sadrzaj iste sirine u bitima        
-OM ima velik kapacitet (10tine ili 100tine GB ili nekoliko TB) ali i znacajno duze vreme odziva        
-procesor pristupa OM u **ciklusima citanja ili upisa**  (engl. read/write memory cycle); zadajuci adresu, podatak i tip operacije(Rd/Wr) **str 55**     
-obezbedjuje direktan pristup lokacijama, u bilo kojem poretku za redom         
-**adresibilna jedinica (engl. addressible unit)** sirina (u bitima) najmanje jedinice koja ima svoju adresu, **1B najcesce**. U zavisnosti od implementacije memorije i sirine magistrale podataka, u jednom ciklusu mogu se preneti 1 ili vise susednih adresibilnih jedinica.        
-**fizicki adresni prostor(engl. physical address space)** skup svih adresa koje se mogu zadati na adresnoj magistrali, skup adresa u opsegu od 0 do 2^n-1, DAKLE NJEGOVA VELICINA JE **2^n B**
-**Instalirana fizicka memorija** je podskup fizickog adr prostora, za koji postoje instalirani memorijski moduli (cipovi) ali hardverski elementi koji se mogu adresirati        
-manja je od fizicke memorije: 4GB, 8GB, 16GB, 256GB, 512GB, 1TB        
--FIZICKI ADRESNI RPOSTOR MOZE BITI POKRIVEN RAZLICITIM TIPOVIMA FIZICKE MEMORIJE--
1.**nepostojani tj dinamicki RAM tj DRAM: Dynamic Random Access Memory**        
-brza memorija sa mogucnosti citanja i upisa        
-gubi sadrzaj gubitkom napajanja        
-u nju se smestaju kernel i procesi tj njihove instrukcije i podaci         
2.**postojani RAM memorija Random Access Memory**        
-sporija od DRAM, sa mogucnoscu citanja i upisa
-NE gubi sadrzaj prilikom napajanja jer ima bateriju ili je izradjena u tehnologiji fles memorije        
-za smestanje sistemskih parametara konfiguracije racunara, npr info o tome koji disk sluzi za podizanje operativnog sistema(boot isk)         
3.**ROM Read Only Memory je perzistentna memorija**        
-nema mogucnost upisa, iz nje se moze samo citati, u nju se upisalo tokom proizvodnje        
-sluzi za smestanje:        
        a)**programa za podizanje sistema (engl. bootstrap program):**         
        -smesta se od:        
                fiksne adrese unapred def za dati procesor
                ILI
                adrese upisane na fiksnoj i unapred defr lokaciji u fizickom adresnom prostoru, koja sadrzi **reset pointer**        
        od te adrese od koje se smesta, procesor pocinje dohvatanje i izvrsavanje instrukcija po svom ukljucivanju: kad pocinje izvrsavanje instrukcija procesor postavlja PC na tu vrednost   
        -uloga u je da vrsi **podizanje sistema (engl.booting)** sa boot diska ucita u memoriju sadrzaj sa unapred definisanog mesta, najcesce blok 0-u kome se nalazi veci bootstrap program, koji dalje sa tog diska ucitava kernel operativnog sistema inicijalizuje ga i stavlja u funkciju, tj pokrece njegovo izvrsavanje        
        b)**BIOS (engl. Basic Input/Output System)**        
        -skup fiksnih, predefinisanih, ugradjenih procedura koje obavljaju osnovne operacije sa u/i hardverskim uredjajima koji su uvek prisutni u racunaru. One procedure OS koristi za implementaciju svojih usluga.        
4.**Memorijski preslikani u/i uredjaji (engl. Memory mapped I/O)**         
  su razliciti u/i uredjaji tj njihovi interfejsi-registri ili mem moduli (npr graficke kartice). Oni se koriste isto kao i celije memorije: procesor  moze izvrsavati cikluse citanja/upisa na lokacije na adresama na koje su oni vezani tj na koje se oni odazivaju. Efekti operacija zavise od implementacije samih elemenata.        
**Mapa fizicke memorije (engl. Memory map)**        
   -definisana je arhitekturom racunara
   -predstavlja raspored opsega memorijskih adresa na kojima mogu biti instalirani memorijski moduli i hardverski elementi  
   -**knjiga strana 58,59 objasnjenje slike i slika**  
   
### ASEMBLER  
-isti termin asembler se koristi za simbolicki masinski jezik tako da ne brkas sa terminom koji oznacava prevodilac programa napisanih na tom programu  
-engl. Assembly  
-radi sledece: simbolicki masinski jezik=>binarni zapis masinskih instrukcija i podataka  
-prevodi jednu po jednu liniju iz ulaznog fajla, izracunava **tekucu adresu** za tu liniju; pocinje od neke unapred definisane adrese koja moze biti 0 ili neka druga vrednost..  
-ukoliko linija sadrzi instrukciju i asembler prepoznaje mnemonik instrukcije:  
        generise binarni kod za tu instrukciju, uzimajuci u obzir operande, ponekad koristi i vrednost tekuce adrese  
        uvecava vrednost tekuce adrese za velicinu binarnog zapisa prevedene instrukcije  
**strana 60,61 objasnjenje asemblerskog koda**  
pored simbolickih masinskih instrukcija, moze sadrzati i **direktive** to je linija asemblerskog teksta koja ne sadrzi instrukciju, vec neku specifikaciju ili uputstvo asembleru
        **direktive:**  
                **DEF** definise simbolicku konstantu u asemblerskom programu  
                simbolickoj konstanti se dodeljuje vrednost konstantnog izraza navedenog u direktivi  
                postize se efekat takav da, gdegod se u kodu pojavi oznaka simbolicke konstante, efekat je isti kao da se naislo na vrednost koju ova konstanta predstavlja, plus pri proveri vrednosti dovoljno je da se promeni samo u def direktivi a u ostatku koda ne treba promena.  
                asembler ubacuje simbol u internih tabelu svojih definisanih simbola
                    **direktiva DEF u picoRISC:**  
                    symbol_name DEF constant_expression ;comment
                **ORG** eksplicitno podesava tekucu adresu linije, postavlja vrednost simnbola $ na novu **zadatu** velicinu  
                   **direktiva ORG na picoRISC**
                   ORG constant_expression ;comment  
                **START** oznacava adresu pocetne instrukcije programa  
                ovu info, koja je na odredjeni nacin zapisana u izlaznom fajlu koristi OS **kada pokrece proces nad ovim programom**  
                   **direktiva START na picoRISC**
                   START constant_expression ;comment        
                **db, dd, dw direktive**  
                npr:  
                hello: db 'H', 'e', 'l', 'l','o' '\n' ;alocira prostor od 6B, u svaki B ubacuje odredjeni simbol, a adresi gde je simvol H dodeljuje labelu hello
                p: dd 0 ;odvaja prostor za dvostruku rec (4B) i inicijalizuje je na 0
                lookup: dw (16 dup 0)  ;odvaja prostor za 16 reci sirine 2B i sve ih inicijalizuje nulama 0; 16 dup 0: znaci 16 puta inicijalizuj adresu vrednoscu 0
        **labela** je simbol pridruzen jednoj liniji asemblerskog programa  
        svakoj labeli na koju naidje asembler dodeljuje vrednost (u svojoj internoj tabeli simbola) tekuce adrese te linije labele($)  
                **sve ovo sa ovim primerima kodova pogledati u knjizi**  

### ADRESIRANJE PODATAKA  
**primere kodova pogledati u knjizi ako treba str. 65-68**
-definise postupak kojim se dolazi do mesta na kojem se nalazi operand instrukcije ili na koji se upisuje rezultat instrukcije  
-da bi masinske instrukcije pristupale podacima, moraju imati odredjene nacine adresiranja(engl. address mode)  
-arhitektura procesora da bi podrzala odgovarajuce kontrukte potrebne u programiranju, ona mora podrzati odredjene nacine adresiranja  
**neposredno adresiranje**  
-engl. immediate address mode  
-operand je binarni sadrzaj u odgovarajucem polju same instrukcije  
#constant_expression  
load r1, #1 npr  
**registrarsko direktno**  
-vazno je da postoji u load/store procesorima jer se time omogucava da se iz memorije vrednosti dovuku u registre i onda nad njima vrse neke operacije  
-operand se nalazi u registru koji je zadat odgovarajucim polje instrukcije  
**registarsko indirektno**  
-koristi se kada se podatku pristupa preko pokazivaca ili za pristup elementu niza...    
-vrednost registra je zadata u odgovarajucem polju instrukcije; u tom registru nalazi se vrednost adrese na kojoj se nalazi podatak  
load r1, [r0]        
**registarsko indirektno sa pomerajem**
-vrednost podatka se nalazi u memoriji na lokaciji koja se dobija sabiranjem vrednosti adrese iz regitra sa pomerajem definisanim u instrukciji  
-pomeraj moze biti negativan  
-pomeraj je na 32b  
**memorijski direktno**  
-o tome je pricao u delu kategorije objekata po zivotnom veku

**Kategorije objekata po zivotnom veku tj trajanju skladista(engl. storage duration)**  
 1.**staticki**  
 -static podatak se alocira za vreme prevodjenja; prevodilac poznaje njegovu adresu, pa se pristup do ovih podataka vrsi **memorijski direktno**  
 2.**lokalni**  
 -njihov zivotni vek vezan je za vreme aktivacije potprograma u kojem se oni koriste 
 -prostor za smestanje ovih objekata(argumenti fjue, povr vr...) se alocira staticki a ti podaci se adresiraju memorijskim direktnim adresiranjem; u pocetku vrednost alociranog podatka je neinicijalizovana  

**Rekurzija**       
-u jednom trenutku moze biti vise aktiviranih istih potprograma (vise nezavrsenih poziva) i svaki od aktiviranih potprograma mora da poseduje svoj skup instanci lokalnih podataka koje odgovaraju istim definicijama tip podataka
-ukoliko dubina rekurzije zavisi od vrednosti argumenta funkcije (kao sto je slucaj sa faktorijelom) onda imamo jednostavniju situaciju  
-ukoliko ne poznajemo dubinu rekurzije:  
  -prilikom poziva potprograma stvara se **aktivacioni blok** - to je blok lokalnih podataka i argumenata; on se postavlja na kraj neke liste. 
  -Instrukcije potprograma treba da referenciraju samo one podatke koji se nalaze u aktivacionom bloku koji je na kraju liste(to su oni podaci    koji su treutno aktuelni jer znamo kako se rekurzija odvija ok) Po povratku iz potprograma, aktivacioni blok sa kraja liste se brise(pa        prethodno pretposlednji blok postaje sada poslednji i tok kontrole dobija poziv odmah iz onog koji se upravo zavrsio)     
  -Stek sluzi za implementaciju ove zamisli; linearna struktura; svaki el ima najvise jednog prethodnika i jednog sledbenika; dostupne su oeracije **push**-smestanje el na vrh steka tj kraj liste i **pop** skidanje vrha steka tj poslednje ubacenog elementa.
    -na vrh steka ukazuje **engl. stack pointer**
    **boldovano se odnosi na picoRISC:**
    -izbor1 pri implementaciji steka: stek moze rasti ka visim ili ka **nizim** lokacijama u memoriji
    -izbor2 pri implementaciji steka: sp moze ukazivati na **prvu slobodnu** ili poslednju zauzetu lokaciju u steku
    **knjiga str 72,73 detaljnije sta se stavlja na stek pri pozivu...**  
-**repna rekurzija** poziv potprograma se odvija na samom kraju tog potprograma izakojeg taj potprogram ne koristi vise svoje lokalne podatke=> uvek mozemo da koristimo jedan aktivacioni blok=>rekurzija se pretvara u **petlju tj iteraciju**

ukoliko se adresiranje podataka odradi nepravilno, npr u niz velicine 5 ti pokusavas da smesti 5 elementata je ok ali ako hoces da pristupa ili upises u sesti element niza deklarisanog na velicinu 5, ti neces znati koji ce biti ishod greske koju si napravio, nepoznate su adrese sa kojih citas ili na koje upisujes, nepoznate su vrednosti na tim adresama...        

### ADRESIRANJE INSTRUKCIJA   
-Instrukcija skoka predstavlja uslovnu ili bezuslovnu promenu vrednosti PC  
-Instrukcija skoka menja vrednost PC, umesto da ima adresu naredne instrukcije, PC ima adresu odredjenu u instrukciji skoka  
-Adresa skoka odredjena je nekim nacinom adresirajna u instrukciji skoka:  
**PC tokom izvrsavanja instrukcije ima vrednost adrese iza tekuce instrukcije**  
**VRSTE ADRESIRANJA:**  
        1.MEMORIJSKO DIREKTNO  
          adresa odredisne instrukcije data je u samom polju instrukcije skoka; **apsolutni skok**  
          jmp loop  
        2.RELATIVNO ADRESIRANJE  
          -najcesce u odnosu na tekucu vredosti registra PC  
          -najcesce se koristi sa uslovnim skokovima  
          -koriscenjem ovog adresiranja neki blok koda (if then else) ili neki potprogram postaje **relokabilan** tj ne zavisi od lokacije na             koju je smesten, jer ukoliko se prebaci na neku drugu adresu nece se morati menjati zapisane adrese u instrukcijama skokova  
         --REGISTARSKO INDIREKTNO SA POMERAJEM  
          odredisna adresa skoka se dobija dodavanjem pomeraja na trenutnu vrednost PC  
          jmp [pc+loop-($+8)] <=> jmp loop  
          racunanjem ovoga u [] dobijamo adresu loop iz tabele simbola, shvatamo da dobijamo istu vrednost adrese, samo smo koristili                    drugacije adresiranje; 8 je duzina tekuce instrukcije (to je verovatno ins skoka) ; ovaj deo loop-($+8) je pomeraj u odnosu na pc  
        3.REGISTARSKO INDIREKTNO  
        pozivi potprograma mogu se vrsiti indirektno, preko pokazivaca  
        call [r0] adresa skoka nalazi se u registru r0
-Nakon izvrsenog skoka na kod nekog potprograma na primer, mora se izvrsiti povratak na tacno narednu instrukciju iza instrukcije skoka; posto potprogrami mogu biti pozvani sa razlicitih mesta adresa povratka se odredjuje dinamicki: povratak iz potprograma se obavlja **indirektnim skokom**:  
        -ukoliko nije podrzana rekurzija, pov adresu pozivalac upisuje odredjenu staticki alociranu **lokaciju u memoriji za tu namenu i taj potprogram ili cak u reg procesora** odakle ce je onda pozvani potprogram procitati prilikom povratka  
        -ukoliko je podrzana rekurzija, pov adresa se prenosi na steku  
**sta se zapravo desava:**  
        PRVA STVAR: instrukcija poziva potprograma (**call na picoRISC**)stavlja staru vrednost pc na stek(adr naredne instrukcije-na nju ce se vratiti nakon povratka iz pp)+ stavlja staru vr PSW registra  
        i  
        u pc stavlja novu vrednsot-adresa pocetka potprograma  
        DRUGA STVAR: instrukcija povratka iz potprograma (**ret na picoRISC**) stavlja su pc vrednost sa vrha steka+kupi staru vr PSW  
(OVO SE IMPLICITNO DESAVA-U POZADINI.. NEMA VEZE SA TELOM FJE I ONIM CIME SE ONA BAVI.. ZATO NE ZABORAVI DA SE NA STEK STAVLJAJU LOKALNI PODACI (...aktivacioni blok; adresiranje podataka...) )  
### PREVODJENJE  

-programi pisani na C/C++ programskim jezicima se **prevode u binarni masinski kod**  
-**Prevodilac (engl. compiler)**
        program koji prevodi kod napisan na visem programskom jeziku kao sto je recimo C/C++ u binarni masinski kod
-Znamo da se program napisan u C/C++ sastoji od vise .c/.cpp fajlova (modula)-svaki ovaj fajl je **jedna jedinica prevodjenja(engl. compilation unit)** to znaci da se **svaki fajl prevodi nezavisno i odvojeno**-prevodilac kada prevodi 1 fajl ne izlazi iz granica tog fajla!!VAZNO!!  
-Prevodjenjem jednog fajla prevodilac stvara jedan **.obj fajl** sa objektnim kodom (engl. object file)
**bilo koja greska u prevodjenju dovodi do toga da se objektini fajl NE GENERISE** IPAK BEZ OBZIRA NA TO **PREVODILAC NASTAVLJA PREVODJENJE** pokusavajuci da prevazidje svaku gresku i **prijavi sve druge greske na koje mozda naidje!!**  


### POVEZIVANJE

        

















