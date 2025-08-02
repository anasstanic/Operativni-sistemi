# Vrste racunarskih i operativnih sistema

## Multiprocesorski i distribuirani sistemi
  Postoje 2 osnovne paradigme hardverske arhitekture rscunarskih sistema koji omogucavaju izvrsavanje programa na vise procesora:
  1) Multiprocesorski sistem:  
     -racunarski sistem sa vise procesora koji dele zajednicku OM-takva je vecina danasnjih racunara  
     -procesori mogu pristupati toj deljenoj memoriji, u nju smestati podatke i citati iz nje  
     -procesorsko jezgro i procesorske niti su hardverski elementi unutar procesora i omogucavaju uporedo izvrsavanje instrukcija vise procesa  
     -Podela multiprocesorskih sistema:  
       -simetrican sistem: svi procesori su opste namene, jednaki su i imaju isto vreme pristupa OM  
       -asimetrican sistem: neki procesori su specijalizovani zaposebne namene, razlicito vreme pristupa OM  
     -Podela OS-ma za multiprocesorske racunare:  
       -simetrican:sve procesore tretira na isti nacin, svi oni **mogu izvrsavati kod procesa i kod kernela**  
       -asimetrican:1 procesor je gazada(engl. master) i on rasporedjuje procese na druge procesore i izvrsava kod kernelea za ostale sistemske usluge; Ostali procesori su robovi i izvrsavaju samo kod korisnickih procesa koje im master dodeli  
     -OS DODATNO MORA DA RASPOREDJUJE PROCESE NA PROCESORE kako bi ih efikasno koristio
  3) Distribuiran sistem:  
     -sistem sa vise procesora koji **NEMAJU** zajednicku OM, vec **svaki procesor ima svoju OM**  
     -procesori su povezani **komunikacionom mrezom** preko koje mogu razmenjivati poruke
     -Podela:
       -specijalizovani racunar sa vise procesora i brzom interkonekcionom mrezom izmedju njih
       -lokalna racunarska mreza (engl. local area network LAN): racunarska mreza sa vise povezanih racunara na relativno malom prostoru
       -mreza sireg podrucja (engl. wide area network WAN): regionalna ili geografski distribuirana mreza
       -Internet
     -Udaljeni pristup podrazumeva pristup jednom racunaru(server) preko drugog udaljenog racunara (klijent) tako sto klijent razmenjuje poruke sa serverom preko racunarske mreze.
     -Nacini na koje klijent interaguje sa OS-om racunara servera: **MALO PRESKOCENO**
       -SSH protokol;sigurna skoljka (engl. secure shell): ovo je protokol za kriptovanu komunikaciju.
       -upomocu udaljenje radne povrsine (engl. remote desktop )
## Personalni racunari
## Serverski sistemi
## Sistemi u oblaku
## Ugradjeni sistemi i sistemi za rad u realnom vremenu
