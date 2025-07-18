#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}--------$1--------${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
    
    if [[ "$OS" != *"Ubuntu"* ]] && [[ "$OS" != *"Debian"* ]]; then
        print_error "This script only supports Ubuntu and Debian"
        exit 1
    fi
}

get_server_ip() {
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "")
    
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP="localhost"
    fi
}

install_php() {
    print_status "Installing PHP 8.4 + Extensions..."
    
    apt update
    apt install -y software-properties-common ca-certificates lsb-release apt-transport-https
    
    LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php
    apt update
    
    apt install -y php8.4 php8.4-{cli,gd,mysql,pdo,mbstring,tokenizer,bcmath,xml,fpm,curl,zip,intl,sqlite3,common,fpm}
    
    print_success "PHP 8.4 and extensions installed successfully"
}

install_nginx() {
    print_status "Installing NGINX..."
    
    apt install -y nginx
    systemctl enable nginx
    systemctl start nginx
    
    print_success "NGINX installed successfully"
}

create_directories() {
    print_status "Creating Directories..."
    
    mkdir -p /var/www/pelican
    cd /var/www/pelican
    
    print_success "Directory /var/www/pelican created"
}

install_files() {
    print_status "Installing Files..."
    
    curl -L https://github.com/pelican-dev/panel/releases/latest/download/panel.tar.gz | tar -xzv
    
    print_success "Pelican Panel files downloaded and extracted"
}

install_composer() {
    print_status "Installing Composer..."
    
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    
    cd /var/www/pelican
    COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --optimize-autoloader
    
    print_success "Composer installed and dependencies resolved"
}

setup_nginx() {
    print_status "Setting up NGINX..."
    
    rm -f /etc/nginx/sites-enabled/default
    
    get_server_ip
    echo ""
    print_warning "Current server IP: $SERVER_IP"
    echo -n "What is your FQDN? (Domain or IP) [Press Enter for $SERVER_IP]: "
    read FQDN < /dev/tty
    
    if [[ -z "$FQDN" ]]; then
        FQDN=$SERVER_IP
    fi
    
    cat > /etc/nginx/sites-available/pelican.conf << EOF
server {
    listen 80;
    server_name $FQDN;
    root /var/www/pelican/public;
    index index.html index.htm index.php;
    charset utf-8;
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }
    access_log off;
    error_log  /var/log/nginx/pelican.app-error.log error;
    client_max_body_size 100m;
    client_body_timeout 120s;
    sendfile off;
    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param PHP_VALUE "upload_max_filesize = 100M \n post_max_size=100M";
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param HTTP_PROXY "";
        fastcgi_intercept_errors off;
        fastcgi_buffer_size 16k;
        fastcgi_buffers 4 16k;
        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_read_timeout 300;
    }
    location ~ /\.ht {
        deny all;
    }
}
EOF
    
    ln -s /etc/nginx/sites-available/pelican.conf /etc/nginx/sites-enabled/pelican.conf
    
    nginx -t
    systemctl restart nginx
    
    print_success "NGINX configuration created and enabled for $FQDN"
}

create_env() {
    print_status "Creating .env..."
    
    cd /var/www/pelican
    php artisan p:environment:setup
    
    print_success ".env file created"
}

set_permissions() {
    print_status "Giving Permissions..."
    
    cd /var/www/pelican
    chmod -R 755 storage/* bootstrap/cache/
    chown -R www-data:www-data /var/www/pelican
    
    print_success "Permissions set correctly"
}

display_completion() {
    print_status "The Web installer is now available."
    echo ""
    print_success "Pelican Panel installation completed successfully!"
    echo ""
    print_warning "Next steps:"
    echo "1. Visit http://$FQDN in your browser"
    echo "2. Complete the web-based setup"
    echo "3. Configure your database settings"
    echo "4. Create your admin account"
    echo ""
    print_warning "Important: Consider setting up SSL/TLS certificates for production use"
}

main() {
    echo -e "${BLUE}--------PELICAN INSTALLATION SCRIPT--------${NC}"
    echo -e "${GREEN}Made by: Verdanox${NC}"
    echo ""
    
    check_root
    detect_os
    
    print_warning "This script will install Pelican Panel on your server."
    print_warning "Operating System: $OS $VERSION"
    print_warning "Installation will start in 5 seconds... Press Ctrl+C to cancel"
    
    sleep 5
    
    echo ""
    
    install_php
    install_nginx
    create_directories
    install_files
    install_composer
    setup_nginx
    create_env
    set_permissions
    display_completion
}

main "$@"
