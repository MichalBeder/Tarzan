Návod na preklad, používanie a ladenie aplikácie.

-------------------------------------------------------------------
I. Preklad
-------------------------------------------------------------------
Priamy preklad aplikácie je možný pomocou nástroja Apache maven
spustenom v koreňovom adresári so zdrojovými súbormi /src.
Príklad príkazu na prekladv nástroji maven:
mvn clean package -DskipTests.
Ďalšou možnosťou je použiť prekladový skript "build.sh" prítomný
takisto v koreňovom adresári /src.
Preložený archív ndx-spark-shell-1.0.jar sa potom nachádza v
adresári src/ndx-spark-shell/target.

-------------------------------------------------------------------
II. Spustenie aplikácie
-------------------------------------------------------------------
Aplikácia potrebuje na svoj beh hostiteľské prostredie, ktoré je
schopné pristupovať k Spark klastru. Príkladmi takýchto
hostiteľských prostredí sú programy spark-shell alebo Apache
Zeppelin.

Program spark-shell je konzolová aplikácia, ktorá je
priamo súčasťou distribúcie Apache Spark.
Načítanie .jar archívu s aplikáciou do programu spark-shell:
spark-shell --jars <path to .jar>/ndx-spark-shell-1.0.jar.
Alternatívne je možné použiť použiť skript "build-and-run.sh"
nachádzajúci sa v adresári /src. Tento skript preloží aplikáciu
a spustí ju v lokálnej inštalácii Sparku.

V Apache Zeppelin 0.8.0 je potrebné vo webovom rozhraní kliknť
v pravom hornom rohu na meno používateľa (napr.anonymous).
Objaví sa menu, v ktorom potrebné zvoliť možnosť "interpreter",
vyhľadať interpreter "spark", kliknúť na "edit" a pridať cestu k
archívu ndx-spark-shell-1.0.jar v položke "Dependencies/artifact".
V adresári src/ sa nachádza súbor "ndx-spark.json", ktorý je možné
načítať na hlavnej stránke webového rozhrania Apache Zeppelin
(položka "Import note"). Tento súbor obsahuje implementáciu volania
aplikácie a zobrazenia dát pre rôzne úlohy spracovania dát sieťovej
komunikácie. Zdroj vstupných dát je možné meniť na 4. riadku
záznamu v premennej "path". Na ďalšom riadku je uvedený zoznam
kľúčových slov vyhľadávaných vo vstupných paketoch.

V obidvoch prípadoch je potrebné najprv importovať aplikačné
rozhranie príkazom "import org.ndx.tshark.scala.TShark". Následne
je možné volať funkcie rozhrania ako napr.
"val packets = TShark.getPackets(sc, path)".

-------------------------------------------------------------------
III. Ladenie aplikácie
-------------------------------------------------------------------
Aplikáciu je možné ladiť v lokálnom režime Sparku. Aplikáciu je
potrebné spustiť v programe spark-shell pomocou skriptov
"build-and-debug.sh" alebo "debug.sh" v adresári /src. Potom je
možné pripojiť sa debuggerom k JVM, v ktorom spark-shell beží a
aplikáciu ladiť.
