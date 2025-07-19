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
        OS_ID=$ID
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
    apt install -y software-properties-common ca-certificates lsb-release apt-transport-https curl gnupg2
    
    if [[ "$OS_ID" == "ubuntu" ]]; then
        # Ubuntu - use Ondrej's PPA
        LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php
        apt update
    elif [[ "$OS_ID" == "debian" ]]; then
        # Debian - use Ondrej's repository
        curl -fsSL https://packages.sury.org/php/apt.gpg | gpg --dearmor -o /usr/share/keyrings/php-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/php-archive-keyring.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list
        apt update
    fi
    
    apt install -y php8.4 php8.4-{cli,gd,mysql,pdo,mbstring,tokenizer,bcmath,xml,fpm,curl,zip,intl,sqlite3,common}
    
    print_success "PHP 8.4 and extensions installed successfully"
}

install_nginx() {
    print_status "Installing NGINX..."
    
    apt install -y nginx
    systemctl enable nginx
    systemctl start nginx
    
    print_success "NGINX installed successfully"
}

install_certbot() {
    print_status "Installing Certbot for SSL certificates..."
    
    apt install -y certbot python3-certbot-nginx
    
    print_success "Certbot installed successfully"
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

check_ssl_certificate() {
    local domain=$1
    if [[ -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]] && [[ -f "/etc/letsencrypt/live/$domain/privkey.pem" ]]; then
        return 0
    else
        return 1
    fi
}

is_valid_domain() {
    local domain=$1
    if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ $domain == "localhost" ]]; then
        return 1
    else
        return 0
    fi
}

setup_ssl() {
    local domain=$1
    
    print_status "Setting up SSL certificate for $domain..."
    
    if check_ssl_certificate "$domain"; then
        print_success "SSL certificate already exists for $domain"
        return 0
    fi
    
    print_warning "Automatically generating SSL certificate for $domain..."
    
    systemctl stop nginx
    
    certbot certonly --standalone --agree-tos --no-eff-email --email admin@$domain -d $domain --non-interactive
    
    if [[ $? -eq 0 ]]; then
        print_success "SSL certificate obtained successfully"
        systemctl start nginx
        return 0
    else
        print_error "Failed to obtain SSL certificate, falling back to HTTP configuration"
        systemctl start nginx
        return 1
    fi
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
    
    USE_SSL=false
    if is_valid_domain "$FQDN"; then
        install_certbot
        
        if check_ssl_certificate "$FQDN"; then
            print_success "SSL certificate found for $FQDN"
            USE_SSL=true
        else
            print_warning "Attempting to automatically generate SSL certificate for $FQDN"
            if setup_ssl "$FQDN"; then
                USE_SSL=true
            else
                print_warning "SSL setup failed, continuing with HTTP configuration"
            fi
        fi
    else
        print_warning "Using IP address - SSL setup skipped"
    fi
    
    if [[ $USE_SSL == true ]]; then
        print_status "Creating SSL NGINX configuration..."
        cat > /etc/nginx/sites-available/pelican.conf << EOF
server_tokens off;
server {
    listen 80;
    server_name $FQDN;
    return 301 https://\$server_name\$request_uri;
}
server {
    listen 443 ssl http2;
    server_name $FQDN;
    root /var/www/pelican/public;
    index index.php;
    access_log /var/log/nginx/pelican.app-access.log;
    error_log  /var/log/nginx/pelican.app-error.log error;
    
    # allow larger file uploads and longer script runtimes
    client_max_body_size 100m;
    client_body_timeout 120s;
    sendfile off;
    
    ssl_certificate /etc/letsencrypt/live/$FQDN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$FQDN/privkey.pem;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
    ssl_prefer_server_ciphers on;
    
    # Security headers
    # See https://hstspreload.org/ before uncommenting the line below.
    # add_header Strict-Transport-Security "max-age=15768000; preload;";
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Robots-Tag none;
    add_header Content-Security-Policy "frame-ancestors 'self'";
    add_header X-Frame-Options DENY;
    add_header Referrer-Policy same-origin;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
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
        print_success "SSL NGINX configuration created for $FQDN"
    else
        print_status "Creating standard NGINX configuration..."
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
        print_success "Standard NGINX configuration created for $FQDN"
    fi
    
    ln -s /etc/nginx/sites-available/pelican.conf /etc/nginx/sites-enabled/pelican.conf
    
    nginx -t
    if [[ $? -eq 0 ]]; then
        systemctl restart nginx
        print_success "NGINX configuration enabled and restarted successfully"
    else
        print_error "NGINX configuration test failed"
        exit 1
    fi
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
    print_status "Installation Complete!"
    echo ""
    print_success "Pelican Panel installation completed successfully!"
    echo ""
    print_warning "Next steps:"
    
    if [[ $USE_SSL == true ]]; then
        echo "1. Visit https://$FQDN/installer in your browser"
    else
        echo "1. Visit http://$FQDN/installer in your browser"
    fi
    
    echo "2. Complete the web-based setup"
    echo "3. Create your admin account"
    echo ""
    
    if [[ $USE_SSL != true ]] && is_valid_domain "$FQDN"; then
        print_warning "SSL certificate could not be obtained automatically"
        echo "You can try running 'certbot --nginx -d $FQDN' manually later"
        echo ""
    fi
    
    print_warning "Important security notes:"
    echo "- Change default passwords immediately"
    echo "- Keep your system updated regularly"
    echo "- Configure firewall rules as needed"
}

main() {
    echo -e "${BLUE}--------PELICAN INSTALLATION SCRIPT--------${NC}"
    echo -e "${GREEN}Made by: Verdanox${NC}"
    echo ""
    
    check_root
    detect_os
    
    print_warning "Installing Pelican Panel on your server..."
    print_warning "Operating System: $OS $VERSION"
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
