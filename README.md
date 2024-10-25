NETWORK NEDİR?
İki yada daha fazla bilgisayarın birbiri ile bağlı olduğu haberleşebildiği yapı.
İnternet te bir network tür. inter arasında net ağ demek.
Networke neden ihtiyaç duyulur: Bilgi transferi, Yazıcı paylaşımı, iletişim, ortak çalışma alanı oluşturma, yedekleme vs…
 
COMMUNICATION - HABERLEŞME NEDİR?
İletişim, iletilmek istenen bilginin hem gönderici hemde alıcı tarafından anlaşıldığı ortamda bilginin bir göndericiden bir alıcıya aktarılma sürecidir Sender- Receiver ilişkisi. 

NETWORK TOPOLOGY - AĞ TOPOLOJİSİ
Network mühendisliği henüz ülkemizde yok ama onun yerine elektronik mühendisleri bu işlerle ilgileniyor. 

Bus Topology

Günümüzde kullanılmıyor. x den y ye veri göndermek istediğinde diğer kişiler tarafından dinlenebilir. Çok da güvenli bir yöntem değil. Sıralı cihaz bağlayabiliyorsun. Hız açısından da olumsuz. Avantajı ile ucuz ve kurulumu kolay. 



Star Topology

Merkezde switch var. Diğer cihazları buna bağlıyorsun.  x den y ye direk bilgiyi gönderebiliyorsun. Daha pahalı ve switch i configure edebilmen lazım. ama kablo koparsa iletişim tamamen kesilir.



Mesh Topology

Bağlantı kopsa da farklı yollardan diğer cihazlara ulaşabiliyor.

LAN(Local Area Network)
Belli bir  bölgedeki cihazları birbirine bağlıyorsan bu LAN olur.Ev, okul, laboratuvar vs.

MAN (Metropolitan Area Network)
Üniversiteler örnek verilebilir. Buradaki LAN ların birbirine bağlanmasıyla MAN oluşur.

WAN (Wide Area Network)
Farklı lokasyonlarda bulunan birden fazla lan ağının birleşmesiyle oluşur. En meşhur geniş olan alan ağı internettir. ISP (internet servis provider) den destek alarak bir alan sahibi olabilirsin. Uluslararası iletişimin sağlanması için yardımcı olan kuruluşlar. Örneğin TürkTelekom, Turkcell vs…

PAN (Personal Area Network) ise bilgisayarına bağladığı mouse klavye vs.


SWITCH & HUB

Bilgisayarların ve diğer ağ öğelerinin birbirine bağlanmasına olarak veren ağ donanımlarından biridir. 
Host = ağa bağlı olan cihazlardır. Bilgisayar, yazıcı vs.
Switch ile hub arasındaki fark

Hub ile x den y ye göndereceğim bilgiyi tüm kullanıcılara gönderir. Çakışmalar oluşabilir. Hız konusunda yavaş. Broadcast bir bilginin ağdaki herkese gönderilmesidir. Switch ile sadece x den y ye bilgiyi gönderir. Ağ trafiği oluşturmaz.

ROUTER

İki farklı ağın birbiriyle haberleşmek için kullanılan donanımsal cihazlardır. Veri paketlerinin ağlar arasında yollarını bulmalarını üstlenir.
Kendi ağımızın dışına çıkmak istediğimizde router kullanmamız gerekir.
Localde ihtiyaç duymayız. Google.com dediğimizde kendi sunucumuzdan çıkıp sunucuya gönderme işini router yapar. Bilginin ne şekilde ne kadar hızlı ulaştırabileceğine karar verir. Bunu routing table tutarak yapabilir. Evdeki interneti farklı cihazlara yönlendirir.
Modem ise daha basit router dır. 

MEDIA ACCESS CONTROL (MAC)
MAC adresi (Fiziksel adres, Donanım adresi), ağ donanımının tanımlanmasını sağlar. MAC Adresi, bilgisayarın ethernet kartına üretici tarafından kodlanan bir bilgidir. Ethernet kartına çalışır bu bilgi. Kendi bilgisayarımızdaki mac adresini şöyle öğrenebiliriz. cmd ekranından `ipconfig /all` yazarak yada sadece `getmac` yazarak öğrenebiliriz. MAC adresi sadece yerel ağda haberleşmeyi sağlar. Yerel ağdan çıktığında bu MAC adresi kullanılmıyor. 





MODEM
Elektriksel sinyali dijital verilere yada dijital verileri elektriksel sinyallere dönüştüren cihaz.
Kablodan gelen analog sinyali dijital sinyale dönüştürüyor. 

FIREWALL (GÜVENLİK DUVARI)
Güvenlik duvarı veya ateş duvarı, güvenlik duvarı yazılımı, bir kural kümesi temelinde ağa gelen giden paket trafiğini kontrol eden donanım tabanlı ağ güvenliği sistemidir. Ağa kim gelmek istiyor yetkisi var mı?
Lamer = basit saldırılar yapabilen kişiler.

Hacker ağa saldırmak istediğinde Firewall dışarıdan girmek isteyen hacker ın ağa erişimi var mı diye bakıyor. Kötü niyetli trafiğe izin vermiyor. Erişmek istenilen porta göre güvenlik kontrolü yapabilir. Donanım ve yazılım tabanlı firewall lar var. Windows güvenlik duvarı software tabanlı bir firewall dır.
Host-based firewall sadece bir cihazı korur. 


PROTOCOL
İki yada daha fazla bilgisayar arasındaki iletişimi sağlamak amacıyla verileri düzenlemeye yarayan, standart olarak kabul edilmiş kurallar dizisidir.
Önceden tanımlanmış kurallar zinciridir. Bilgisayarların iletişimini sağlayan kurallardır. Protocol olmasa bir karmaşa olur. Bizler IP protocol ü kullanıyoruz.  Apple protocol ü AppleTalk, X firması XProtocol diyebilir. 
Bu standartları belirleyen firma ISO (International Organization for Standardization)
OSI (Open System Interconnection) = Bir protocol oluştururken hangi katmanların olacağına karar veren protokoldür. OSI bir protocol değil bir modeldir.

OSI (OPEN SYSTEM INTERCONNECTION)



Geçmişte farklı firmalar farklı kurallar ile iletişim kurunca karışıklığa sebep oldu. Ortak arayüz olması için ISO ortak bir sistem teklif etti. Buda OSI standardıdır. Ağ haberleşmesi yapmak istediğimizde bir klavuz görevi görüyor. 


1- Physical Layer
OSI referans modelindeki en alt katman. İki cihazın birbine fiziksel olarak bağlamaktır. Bakır, Fiber optik, wi-fi vs. Application dan başlayarak fiziksel katmana kadar inerek 0,1 lere dönüştürülüyor. Daha sonra bu 0,1 ler application katmanına yeniden yükseliyor.

2- DataLink

İki PC haberleşirken her katmanda birşeyler oluyor.Capsulation ve Decapsulation işlemleri yapılıyor. DataLink katmanında Frame eklenerek physical katmana aktarıyor.

LLC(Logical Link Control) = ağ katmanı protokollerinin tanımlanması daha sonra çözülmesi ve hata kontrollerinin sağlanmasından sorumludur.

Günümüzde veri bağlantısı katmanı olarak ethernet protokolünü kullanıyoruz. 

3- Network
Kendi localimizden çıkıp farklı ağlarla haberleşmeyi sağlıyor. Farklı ağlardan haberleşmeden bahsediyorsak buna Packets denir. Aynı ağdaki farklı bilgisayarlarla iletişime Frame denir. Router bu katmanda çalışıyor. 
Haberleşmek için IP protokolünü kullanıyor. Farklı cihazlar arası iletişim kurulabiliyor. Yönlendirme protokoller RIP, IGRP, EIGRP ile farklı ağlar ile en kestirme yol bulunur.







4- Transport
Session ile Network katmanı arasındadır. ilk 3 katmanda data sıkıştırılıyor. Segmentation (parçalama) işlemi yapılıyor. Data parçalandıktan sonra 10 parçaya bölündüyse datanın önüne ve arkasına parça numaraları ekleniyor. ve Flow control yani karşı tarafın hızı kontrol ediliyor. Ona göre paket işlemi yapılıyor. Sonra Error control ile data sağlıklı bir şekilde geldi mi diye kontrol ediliyor. Verinin güvenliğinin sağlanması TCI, UDP verinin alıp alınmadığına bakmadan transfer edilir. Mesela canlı yayınca UDP kullanılır. 

5- Session Layer
Bu katmanda iki işlem yapılıyor. Birincisi Authentication diğeri Authorization. Facebook, instagram gibi sitelerde şifre ile girip kimlik doğrulamaya Authentication deniyor. Benim yetkilerime ise Authorization deniyor. Bir uygulamanın basit premium gibi yetkilerine de Authorization oluyor. 

6- Presentation
Bu katmanda bilginin iletimde kullanılacak şekilde düzenlenir. Encryption, Decryption, Compression işlemleri yapılıyor. Gönderilen verilen örneğin SSL ile şifreleniyor ve karşı tarafa aktarılıyor. Karşı taraf ile Decryption yapılıyor. Compression ile data sıkıştırılıyor.

7-Application
Son kullanıcıya en yakın katmandır. Bu katmanda soket programlama yapacağız.
Browser → http veya https 
Email → smtp
File transfer →ftp
virtual terminal → Telnet
application katmanında bu uygulamalar yazılıyor.


TCP/IP (Transmission Control Protocol) ve IP (Internet Protocol)


Günümüzde bilgisayar ağları arasında en çok kullanılan protokoldür. OSI referans modeline alternatif olarak ABD tarafından geliştirilmiştir. 



IP Adresi
Ağlarda her bir cihazın bir tane bulundurması gereken bir değerdir. IP adresine sahip farklı iki farklı cihaz aynı ağda olmasa dahi, yönlendiriciler (router) vasıtasıyla birbirleriyle iletişim kurabilirler.
Router paketleri yönlendirerek birbirine yönlendiriyorlar. Burada kaynak IP adresi ve hedef IP adresi ile birbirini bulur. 
Yönlendirme işlevi sayesinde internet çalışmasını sağlar ve internetin olmazsa olmazıdır. IP, paket teslim görevini paket başlıklarındaki IP adresine dayalı olarak kaynak adresten hedef adrese doğru gerçekleşir. 
Public IP = internete çıkarken kullanılan ip adresi.
Local IP = Bulunduğumuz local ağda kullanılan ip adresi.

X.X.X.Y
Buradaki ilk 3 adres aynı ağda olduğunu gösterir. Y ile host u gösterir.
iki cihaza da aynı ip adresini verirse ip conflict olur. Her web sitesinin de bir ip adresi vardır.


PING
Ping programı, 1983 yılında Mike Muuss tarafından yazılmış bir programdır. Bir makineye genelde 32 baytlık bir ICMP paketi gönderir ve aynı paketin geri gelmesini bekler. 

Request time out = karşı taraf kapalı yada güvenlik duvarı olabilir.
bağlantının yüzde 10 gibi bir kısmı ulaşırsa kabloda yada modemde bir sorun olduğunu gösterir. 
host unreachable = ağ bağlantısının olmadığını gösterir.
Ethernet kartı düzgün bir şekilde çalışıyor mu = ping 127.0.0.1


SOCKET PROGRAMLAMA

Socket oluşturulması socket()

Soketin bind edilmesi bind() hangi port, hangi network kartı ile ilgilendiğimizi belirleyeceğiz.

Soketin dinlenmesi listen() client tan gelen isteklerin bir kuyruğa konularak bize gönderilmesi. Dinleme işlemi başka birisi aynı portu kullanıyorsa başarısız olur.
istekler FIFO kuyruk yapısı ile gelir. 

Soketin kabulü accept() listen daki bağlantı isteğini kabul ediyoruz. Sonra accept fonksiyonu yeni bir soket veriyor bize. Biz o bağlantı ile konuşabiliyoruz.

Read-Write işlemi artık yapılabilir. Bu arada aynı anda birden fazla programla konuşabiliriz.

Shutdown() fonksiyonu ile soketi kapatmamız gerekir. zorunlu değil ama yapılırsa iyi olur.

close() ile çıkış yapılır.

Socket Function( #include sys/socket.h)

int socket(int domain, int type, int protocol);
Domain:  hangi protocol ailesini kullanacağız.which protocol family. ipV4 ile çalışacaksak 
AF_XXX —> AP_INET4 : IPV4 yada AF_INET6:IpV6 yada AF_APPLETALK  yada AF_UNIX

Type: kullanılacak protokolün türünü seçeceğiz. Mesele IP protokolünde TCI / UDP gibi bir tür seçeceğiz. 
SOCK_STREAM -> TCP
SOCK_DATAGRAM ->UDP

Protocol: ZERO(IP Family) Transport Layer olduğunu biliyoruz. Bunların dışında IPPROTO_TCP, IPPROTO_UDP için netinet.h dosyasını include etmeliyiz.

Return value: başarısızlık durumunda -1 döndürür. return -1 on error other return file discritor döndürecek.

Bind Fonksiyonu ( #include <sys/socket.h> )

int bind(int socket, const struct sockaddr* address, socklent_t address_len);

return value: successful return 0, otherwise return -1

socket: hangi soketi bind edeceksen onun file descriptor ını buraya geçmek gerekir.

address: hangi portu dinleyeceksek onu bind edeceğiz.(which port and NIC).
struct sockadd_in4 → Ipv4
struct sockadd_in6 → Ipv6
address_len: ikinci parametrenin sizeof() unu belirleyeceğiz.

struct sockaddr_in serverAddr; şeklinde bu structurı dolduralım.
int server_fd = socket(AF_INET, SOCK_STREAM, 0);
bind(server_fd,(sockaddr*) &serverAddr, sizeof(server_addr));, 

struct sockaddr_in ipv4 için bu struct kullanılıyordu. 

struct sockaddr_in{
	short sin_family; -> Kullanılacak protokolün ailesi
	unsigned short sin_port; -> Server Hangi portu kullanacak.
	struct in_addr sin_addr; ->Server dan gelecek ip adresini istiyor.
}
struct sockaddr_in serverAddr;
serverAddr.sin_famiy = AF_INET;
serverAddr.sin_port = htons(2050);
serverAddr.sin_addr = htonl(INADDR_ANY); cihaza bağlı olan tüm network kartlarından gelen bilgiler

htons = host network byte ordering short (2byte)
htonl = host network byte orderin long (4 byte)


Listen Fonksiyonu

int listen(int socket, int backlog);
backlog uzunluğunu belirleyip FIFO ya göre sıraya almasını sağlayacağız. Örneğin 5 backlog belirlediğimizde 6. istek geldiğinde bunu önce bekletecek ve onun yerine boşalan adrese yerleşecek.


Accept Fonksiyonu

Gelen bağlantıyı kabul ederek artık konuşmaya başlayabiliriz. Backlog dan gelen bağlantı isteklerini kabul ediyoruz. Kuyruk boş ile blokeli modda bekler. 

int accept(int socket, struct sockaddr* restrict address, socklen_t* address_len);
socket: soket file descriptor
sockaddr: hangi IP adresi ve hangi porttan bağlantı kuruldu. sockaddr_in →Ipv4, NULL olabilir.
address_len: 2. parametrenin byte uzunluğunun yerleştirildiği adres.
return value: başarı durumunda yeni bir soket oluşturulur konuşma soketi başarızlık durumunda -1 döner.

Example:
struct sockaddr_in addr_client;
socklen_t addr_len;
addr_len= sizeof(addr_client);

int client_socket;
client_socket = accept(sock,(struct sockaddr*)&addr_client, &addr_len);

