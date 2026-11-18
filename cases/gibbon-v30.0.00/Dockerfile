FROM wordpress:php8.3-apache

RUN docker-php-ext-install pdo_mysql gettext \
    && a2enmod rewrite
