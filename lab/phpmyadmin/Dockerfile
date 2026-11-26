# phpMyAdmin 4.8.1 (Vulhub) avec sa configuration COPIÉE dans l'image.
# Un fichier monté depuis Windows arrive avec des droits 777 : phpMyAdmin refuse alors
# de démarrer (« Wrong permissions on configuration file, should not be world writable! »).
FROM vulhub/phpmyadmin:4.8.1
COPY config.inc.php /var/www/html/config.inc.php
RUN chown root:root /var/www/html/config.inc.php && chmod 644 /var/www/html/config.inc.php
