FROM php:8.0-apache

RUN a2enmod rewrite

## Basic tools
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y bash \
            curl \
            wget \
            ca-certificates \
            nano \
            libfreetype6-dev \
            libjpeg62-turbo-dev \
            libpng-dev \
            libxrender1 libfontconfig \
            libicu-dev \
            libonig-dev \
            libxml2-dev \
            libmcrypt-dev \
            zip libzip-dev unzip \
        && docker-php-ext-configure gd --with-freetype=/usr/include/ --with-jpeg=/usr/include/ \
        && docker-php-ext-install pdo_mysql gd mbstring bcmath zip intl opcache \
        && docker-php-ext-enable intl opcache

## Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

## Symfony cache folder
RUN groupadd dev -g 999
RUN useradd dev -g dev -d /var/www/symfony -m
RUN chown -R dev:dev /var/www/symfony

WORKDIR /var/www/symfony
