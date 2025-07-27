# Uvod u operativne sisteme

## Sta je operativni sistem?

Operativni sistem (eng. Operating system) je **program(softver)** koji:
-neposredno **rukuje hardverom racunara**
-omogucava **izvrsavanje korisnickih programa** na racunaru i 
-sluzi kao **posrednik izmedju korisnickih programa i hardvera** pruzajuci usluge tim programima

Operativni sistem je **sistemski softver**, za razliku od aplikativnog softvera koji se koristi za specificne zadatke. OS omogucava odgovarajuce usluge korisnickim programima.

Operativni sistem je skup rutina koje obavljaju operacije sa hardverskim uredjajima racunara, koje se nalaze u memoriji racunara i koje se mogu koristiti kao usluge. Te usluge korisnicki programi pozivaju kao **sistemske pozive**(engl. system calls). Sistemski pozivi predstavljaju nacin da korisnicki program zahteva neku uslugu OS-a tj mehanizam kojim korisnicki program poziva rutine operativnog sistema; **getc i putc su potprogrami** koji se mogu naci u korisnickim programima, oni u svojoj implementacji imaju sistemske pozive kojim zahtevaju pomenute usluge od operativnog sistema na kojem se program izvrsava.

**Jednostavni ugradjeni sistemi** (engl. embedded systems) mogu da rade bez operativnog sistema jer izvrsavaju samo jedan program, imaju **bibliotecni OS** (engl. library operating system) u kojem se **rutine** koje implementiraju funkcionalnosti koje su opste i spadaju u odgovornost operativnog sistema, povezuju sa programom kao biblioteke. Slozeniji ugradjeni sistemi imaju klasican OS.

## Koje su osnovne funkcije OS-a?

1) omogucava pokratanje izvrsavanja, izvrasavanje programa ( jednog ili vise njih uporedo) na hardveru racunara
2) omogucava sto efikasnije uporedo izvrsavanje programa
3) fizickih resursa za izvrsavanje programa je ograniceno mnogo, os se trudi da imamo logicki neogranicen kapacicet resursa
4) omogucava obavljanje ulazno-izlaznih operacija pomocu uredjaja koje racunar poseduje
5) komunikacija izmedju programa koji se odvijaju na 1 ili vise racunara
6) omogucava programima pristup i operacije nad fajlovima na istim ili udaljenim racunarom/ima
7) zastita od nezeljenog uticaja izvrsavanja jednog programa na izvrsavanje drugih programa
8) zastita od malicioznih softvera i drugih neovlascenih pristupa
9) omogucava nacin na koji korisnici sa njim interaguju koriscenjem **korisnickog interfejsa** (engl. user interface)

## Delovi operativnog sistema:

### jezgro (engl. kernel)
### sistemski programi
### korisnicki interfejs




















