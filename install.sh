#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_REDIS=false
REDIS_PASSWORD=""

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

generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
}

check_pelican_installation() {
    if [[ -d "/var/www/pelican" ]] && [[ -f "/var/www/pelican/artisan" ]]; then
        return 0
    else
        return 1
    fi
}

show_management_menu() {
    print_status "Pelican Management Menu"
    echo "Pelican Panel is already installed on this server."
    echo ""
    echo "What would you like to do?"
    echo "1. Uninstall Pelican"
    echo "2. Get Panel Logs"
    echo "3. Fix Permissions"
    echo "4. Change Panel Domain"
    echo "5. Install Redis"
    echo "6. Update Panel"
    echo "7. Exit"
    echo ""
    
    while true; do
        echo -n "Please select an option [1-7]: "
        read -r choice < /dev/tty
        case $choice in
            1)
                uninstall_pelican
                break
                ;;
            2)
                get_panel_logs
                break
                ;;
            3)
                fix_permissions
                break
                ;;
            4)
                change_panel_domain
                break
                ;;
            5)
                install_redis_management
                break
                ;;
            6)
                update_panel
                break
                ;;
            7)
                print_success "Exiting..."
                exit 0
                ;;
            *)
                print_error "Invalid option. Please select 1-7."
                ;;
        esac
    done
}

uninstall_pelican() {
    print_status "Uninstalling Pelican Panel"
    echo ""
    print_error "WARNING: This will completely remove Pelican Panel from your server!"
    print_error "ALL PANEL DATA INCLUDING DATABASE WILL BE LOST!"
    print_warning "Game servers will continue to exist but will no longer be managed by the panel."
    echo ""
    echo -n "Are you absolutely sure you want to uninstall Pelican Panel? (type 'YES' to confirm): "
    read -r confirmation < /dev/tty
    
    if [[ "$confirmation" != "YES" ]]; then
        print_warning "Uninstallation cancelled."
        exit 0
    fi
    
    print_status "Removing Pelican Panel files..."
    
    systemctl disable --now pelican-queue 2>/dev/null || true
    rm -f /etc/systemd/system/pelican-queue.service 2>/dev/null || true
    
    rm -rf /var/www/pelican
    
    rm -f /etc/nginx/sites-enabled/pelican.conf
    rm -f /etc/nginx/sites-available/pelican.conf
    
    systemctl restart nginx
    
    print_success "Pelican Panel has been completely removed from your server"
    print_warning "Note: Database, PHP, Nginx, and other system packages were not removed"
    print_warning "Game servers are still running but are no longer managed by the panel"
}

get_panel_logs() {
    print_status "Retrieving Panel Logs"
    
    if [[ ! -d "/var/www/pelican/storage/logs" ]]; then
        print_error "Panel logs directory not found"
        exit 1
    fi
    
    LOG_FILE="/var/www/pelican/storage/logs/laravel-$(date +%F).log"
    
    if [[ ! -f "$LOG_FILE" ]]; then
        print_error "Today's log file not found: $LOG_FILE"
        print_warning "Available log files:"
        ls -la /var/www/pelican/storage/logs/laravel-*.log 2>/dev/null || print_error "No log files found"
        exit 1
    fi
    
    print_status "Uploading logs to logs.pelican.dev..."
    
    LOG_URL=$(tail -n 300 "$LOG_FILE" | curl --data-binary @- https://logs.pelican.dev 2>/dev/null)
    
    if [[ $? -eq 0 ]] && [[ -n "$LOG_URL" ]]; then
        print_success "Logs uploaded successfully!"
        echo "Log URL: $LOG_URL"
    else
        print_error "Failed to upload logs to logs.pelican.dev"
        print_warning "Showing last 50 lines of today's log instead:"
        echo ""
        tail -n 50 "$LOG_FILE"
    fi
}

fix_permissions() {
    print_status "Fixing Pelican Panel Permissions"
    
    if [[ ! -d "/var/www/pelican" ]]; then
        print_error "Pelican Panel directory not found"
        exit 1
    fi
    
    cd /var/www/pelican
    
    print_status "Setting correct file permissions..."
    chmod -R 755 storage/* bootstrap/cache/ 2>/dev/null || true
    
    print_status "Setting correct ownership..."
    chown -R www-data:www-data /var/www/pelican
    
    print_success "Permissions fixed successfully"
    print_warning "If you're still experiencing permission issues, you may need to check SELinux settings or file system permissions"
}

install_redis_management() {
    print_status "Redis Installation"
    
    if command -v redis-server &> /dev/null; then
        print_warning "Redis is already installed on this system"
        echo -n "Do you want to reconfigure Redis for Pelican? (y/N): "
        read -r choice < /dev/tty
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            print_success "Redis installation skipped"
            return 0
        fi
    fi
    
    print_status "Installing Redis..."
    
    curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list
    
    apt update -y
    apt install -y redis-server
    
    systemctl enable --now redis-server
    
    print_success "Redis installed successfully"
    
    REDIS_PASSWORD=$(generate_password)
    
    print_status "Configuring Redis authentication..."
    
    redis-cli ACL SETUSER default on >"$REDIS_PASSWORD" allcommands allkeys 2>/dev/null || {
        print_warning "Failed to set Redis password via CLI, updating configuration file..."
    }
    
    if ! grep -q "requirepass" /etc/redis/redis.conf; then
        echo "requirepass $REDIS_PASSWORD" >> /etc/redis/redis.conf
    else
        sed -i "s/^requirepass.*/requirepass $REDIS_PASSWORD/" /etc/redis/redis.conf
    fi
    
    if [[ -f /etc/redis/users.acl ]]; then
        if grep -q "user default" /etc/redis/users.acl; then
            sed -i "s/user default.*/user default on >$REDIS_PASSWORD allcommands allkeys/" /etc/redis/users.acl
        else
            echo "user default on >$REDIS_PASSWORD allcommands allkeys" >> /etc/redis/users.acl
        fi
    else
        echo "user default on >$REDIS_PASSWORD allcommands allkeys" > /etc/redis/users.acl
    fi
    
    systemctl restart redis-server
    
    print_success "Redis configured with authentication"
    
    cat > /var/www/pelican/redis-credentials.txt << EOF
Redis Installation Details:
==========================
Redis Password: $REDIS_PASSWORD
Redis Host: 127.0.0.1
Redis Port: 6379

You can use these credentials in your Pelican Panel .env file:
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=$REDIS_PASSWORD
REDIS_PORT=6379
CACHE_DRIVER=redis
QUEUE_CONNECTION=redis
SESSION_DRIVER=redis

EOF
    
    chown www-data:www-data /var/www/pelican/redis-credentials.txt
    chmod 600 /var/www/pelican/redis-credentials.txt
    
    print_success "Redis credentials saved to /var/www/pelican/redis-credentials.txt"
    
    echo ""
    print_warning "To complete the Redis setup for Pelican Panel, run these commands:"
    echo "cd /var/www/pelican"
    echo "php artisan p:redis:setup"
    echo ""
    print_warning "Redis Configuration Details:"
    echo "Host: 127.0.0.1"
    echo "Port: 6379"
    echo "Password: $REDIS_PASSWORD"
    echo ""
    print_warning "Please save this password - you'll need it for Pelican Panel configuration"
}

update_panel() {
    print_status "Updating Pelican Panel"
    
    if [[ ! -d "/var/www/pelican" ]]; then
        print_error "Pelican Panel directory not found"
        exit 1
    fi
    
    echo ""
    print_warning "This will update your Pelican Panel to the latest version"
    print_warning "Make sure you have a backup of your panel before proceeding"
    echo -n "Do you want to continue with the update? (y/N): "
    read -r choice < /dev/tty
    
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        print_warning "Panel update cancelled"
        exit 0
    fi
    
    cd /var/www/pelican || {
        print_error "Could not change to panel directory"
        exit 1
    }
    
    print_status "Putting Panel in Maintenance Mode..."
    php artisan down
    print_success "Panel is now in maintenance mode"
    
    print_status "Downloading Update..."
    curl -L https://github.com/pelican-dev/panel/releases/latest/download/panel.tar.gz | tar -xzv
    if [[ $? -eq 0 ]]; then
        print_success "Update files downloaded successfully"
    else
        print_error "Failed to download update files"
        php artisan up
        exit 1
    fi
    
    print_status "Giving Permissions..."
    chmod -R 755 storage/* bootstrap/cache/ 2>/dev/null || true
    print_success "File permissions updated"
    
    print_status "Updating Dependencies..."
    COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --optimize-autoloader
    if [[ $? -eq 0 ]]; then
        print_success "Dependencies updated successfully"
    else
        print_error "Failed to update dependencies"
        php artisan up
        exit 1
    fi
    
    print_status "Creating Storage Links..."
    php artisan storage:link
    print_success "Storage links created"
    
    print_status "Renewing Cache Components..."
    php artisan optimize:clear
    php artisan optimize
    print_success "Cache components renewed"
    
    print_status "Updating Database..."
    php artisan migrate --seed --force
    if [[ $? -eq 0 ]]; then
        print_success "Database updated successfully"
    else
        print_error "Database migration failed"
        php artisan up
        exit 1
    fi
    
    print_status "Setting Permissions for Webserver..."
    chown -R www-data:www-data /var/www/pelican
    print_success "Webserver permissions set"
    
    print_status "Restarting Queue Workers..."
    php artisan queue:restart
    print_success "Queue workers restarted"
    
    print_status "Disabling Maintenance Mode..."
    php artisan up
    print_success "Panel is now live again"
    
    echo ""
    print_success "Panel update completed successfully!"
    print_warning "Please verify that your panel is working correctly"
    print_warning "Check the panel logs if you encounter any issues"
}

change_panel_domain() {
    print_status "Changing Panel Domain"
    
    if [[ ! -f "/etc/nginx/sites-available/pelican.conf" ]]; then
        print_error "Pelican nginx configuration not found"
        exit 1
    fi
    
    CURRENT_DOMAIN=$(grep -m1 "server_name" /etc/nginx/sites-available/pelican.conf | awk '{print $2}' | sed 's/;//g')
    
    get_server_ip
    echo ""
    print_warning "Current domain/IP: $CURRENT_DOMAIN"
    print_warning "Server IP: $SERVER_IP"
    echo -n "Enter new domain or IP [Press Enter for $SERVER_IP]: "
    read NEW_DOMAIN < /dev/tty
    
    if [[ -z "$NEW_DOMAIN" ]]; then
        NEW_DOMAIN=$SERVER_IP
    fi
    
    if [[ "$NEW_DOMAIN" == "$CURRENT_DOMAIN" ]]; then
        print_warning "New domain is the same as current domain. No changes made."
        exit 0
    fi
    
    cp /etc/nginx/sites-available/pelican.conf /etc/nginx/sites-available/pelican.conf.backup
    
    USE_SSL=false
    if is_valid_domain "$NEW_DOMAIN"; then
        print_status "Valid domain detected. Checking SSL options..."
        
        if ! command -v certbot &> /dev/null; then
            print_status "Installing Certbot..."
            apt update
            apt install -y certbot python3-certbot-nginx
        fi
        
        if check_ssl_certificate "$NEW_DOMAIN"; then
            print_success "SSL certificate already exists for $NEW_DOMAIN"
            USE_SSL=true
        else
            print_warning "No SSL certificate found for $NEW_DOMAIN"
            echo -n "Do you want to generate an SSL certificate for $NEW_DOMAIN? (y/N): "
            read -r ssl_choice < /dev/tty
            
            if [[ "$ssl_choice" =~ ^[Yy]$ ]]; then
                if setup_ssl "$NEW_DOMAIN"; then
                    USE_SSL=true
                else
                    print_warning "SSL setup failed, continuing with HTTP configuration"
                fi
            else
                print_warning "Skipping SSL certificate generation"
            fi
        fi
    else
        print_warning "Using IP address - SSL setup skipped"
    fi
    
    print_status "Generating new nginx configuration..."
    
    if [[ $USE_SSL == true ]]; then
        print_status "Creating SSL NGINX configuration..."
        cat > /etc/nginx/sites-available/pelican.conf << EOF
server_tokens off;
server {
    listen 80;
    server_name $NEW_DOMAIN;
    return 301 https://\$server_name\$request_uri;
}
server {
    listen 443 ssl http2;
    server_name $NEW_DOMAIN;
    root /var/www/pelican/public;
    index index.php;
    access_log /var/log/nginx/pelican.app-access.log;
    error_log  /var/log/nginx/pelican.app-error.log error;
    
    # allow larger file uploads and longer script runtimes
    client_max_body_size 100m;
    client_body_timeout 120s;
    sendfile off;
    
    ssl_certificate /etc/letsencrypt/live/$NEW_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$NEW_DOMAIN/privkey.pem;
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
        print_success "SSL NGINX configuration created for $NEW_DOMAIN"
    else
        print_status "Creating standard NGINX configuration..."
        cat > /etc/nginx/sites-available/pelican.conf << EOF
server {
    listen 80;
    server_name $NEW_DOMAIN;
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
        print_success "Standard NGINX configuration created for $NEW_DOMAIN"
    fi
    
    nginx -t
    if [[ $? -eq 0 ]]; then
        systemctl restart nginx
        print_success "Domain changed from $CURRENT_DOMAIN to $NEW_DOMAIN"
        print_success "Nginx restarted successfully"
        
        if [[ $USE_SSL == true ]]; then
            print_success "SSL certificate configured successfully"
            echo ""
            print_warning "Your panel is now available at: https://$NEW_DOMAIN"
        else
            echo ""
            print_warning "Your panel is now available at: http://$NEW_DOMAIN"
        fi
        
        echo ""
        print_warning "IMPORTANT: You may need to update the following:"
        print_warning "1. Panel URL in your .env file (APP_URL)"
        if [[ $USE_SSL == true ]]; then
            print_warning "   Set APP_URL=https://$NEW_DOMAIN"
        else
            print_warning "   Set APP_URL=http://$NEW_DOMAIN"
        fi
        print_warning "2. Wings configuration files on all nodes"
        print_warning "3. Any custom configurations that reference the old domain"
        
        rm -f /etc/nginx/sites-available/pelican.conf.backup
        
    else
        print_error "Nginx configuration test failed. Restoring backup..."
        mv /etc/nginx/sites-available/pelican.conf.backup /etc/nginx/sites-available/pelican.conf
        systemctl restart nginx
        print_error "Domain change failed. Original configuration restored."
        exit 1
    fi
}

ask_redis_installation() {
    print_status "Redis Installation Option"
    echo "Do you want to install Redis? (For Caching, Queue etc.)"
    echo "1. Install Redis"
    echo "2. Don't Install Redis"
    echo ""
    while true; do
        echo -n "Please select an option [1-2]: "
        read -r choice < /dev/tty
        case $choice in
            1)
                INSTALL_REDIS=true
                print_success "Redis installation selected"
                break
                ;;
            2)
                INSTALL_REDIS=false
                print_success "Skipping Redis installation"
                break
                ;;
            *)
                print_error "Invalid option. Please select 1 or 2."
                ;;
        esac
    done
    echo ""
}

install_php() {
    print_status "Installing PHP 8.4 + Extensions..."
    
    apt update
    apt install -y software-properties-common ca-certificates lsb-release apt-transport-https curl gnupg2
    
    if [[ "$OS_ID" == "ubuntu" ]]; then
        LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php
        apt update
    elif [[ "$OS_ID" == "debian" ]]; then
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

install_redis() {
    if [[ $INSTALL_REDIS != true ]]; then
        return 0
    fi
    
    print_status "Installing Redis..."
    
    curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list
    
    apt update -y
    apt install -y redis-server
    
    systemctl enable --now redis-server
    
    REDIS_PASSWORD=$(generate_password)
    
    redis-cli ACL SETUSER default on >"$REDIS_PASSWORD" allcommands allkeys
    
    echo "requirepass $REDIS_PASSWORD" >> /etc/redis/redis.conf
    
    systemctl restart redis-server
    
    print_success "Redis installed and configured successfully"
    print_warning "Redis Password: $REDIS_PASSWORD"
    print_warning "Please save this password - you'll need it for Pelican Panel configuration"
    
    cat > /var/www/pelican/redis-credentials.txt << EOF
Redis Installation Details:
==========================
Redis Password: $REDIS_PASSWORD
Redis Host: 127.0.0.1
Redis Port: 6379

You can use these credentials in your Pelican Panel .env file:
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=$REDIS_PASSWORD
REDIS_PORT=6379
CACHE_DRIVER=redis
QUEUE_CONNECTION=redis
SESSION_DRIVER=redis

EOF
    
    chown www-data:www-data /var/www/pelican/redis-credentials.txt
    chmod 600 /var/www/pelican/redis-credentials.txt
    
    print_success "Redis credentials saved to /var/www/pelican/redis-credentials.txt"
}

install_redis_management() {
    print_status "Redis Installation"
    
    if command -v redis-server &> /dev/null; then
        print_warning "Redis is already installed on this system"
        echo -n "Do you want to reconfigure Redis for Pelican? (y/N): "
        read -r choice < /dev/tty
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            print_success "Redis installation skipped"
            return 0
        fi
    fi
    
    print_status "Installing Redis..."
    
    curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list
    
    apt update -y
    apt install -y redis-server
    
    systemctl enable --now redis-server
    
    print_success "Redis installed successfully"
    
    REDIS_PASSWORD=$(generate_password)
    
    print_status "Configuring Redis authentication..."
    
    redis-cli ACL SETUSER default on >"$REDIS_PASSWORD" allcommands allkeys 2>/dev/null || {
        print_warning "Failed to set Redis password via CLI, updating configuration file..."
    }
    
    if ! grep -q "requirepass" /etc/redis/redis.conf; then
        echo "requirepass $REDIS_PASSWORD" >> /etc/redis/redis.conf
    else
        sed -i "s/^requirepass.*/requirepass $REDIS_PASSWORD/" /etc/redis/redis.conf
    fi
    
    if [[ -f /etc/redis/users.acl ]]; then
        if grep -q "user default" /etc/redis/users.acl; then
            sed -i "s/user default.*/user default on >$REDIS_PASSWORD allcommands allkeys/" /etc/redis/users.acl
        else
            echo "user default on >$REDIS_PASSWORD allcommands allkeys" >> /etc/redis/users.acl
        fi
    else
        echo "user default on >$REDIS_PASSWORD allcommands allkeys" > /etc/redis/users.acl
    fi
    
    systemctl restart redis-server
    
    print_success "Redis configured with authentication"
    
    cat > /var/www/pelican/redis-credentials.txt << EOF
Redis Installation Details:
==========================
Redis Password: $REDIS_PASSWORD
Redis Host: 127.0.0.1
Redis Port: 6379

You can use these credentials in your Pelican Panel .env file:
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=$REDIS_PASSWORD
REDIS_PORT=6379
CACHE_DRIVER=redis
QUEUE_CONNECTION=redis
SESSION_DRIVER=redis

EOF
    
    chown www-data:www-data /var/www/pelican/redis-credentials.txt
    chmod 600 /var/www/pelican/redis-credentials.txt
    
    print_success "Redis credentials saved to /var/www/pelican/redis-credentials.txt"
    
    echo ""
    print_warning "To complete the Redis setup for Pelican Panel, run these commands:"
    echo "cd /var/www/pelican"
    echo "php artisan p:redis:setup"
    echo ""
    print_warning "Redis Configuration Details:"
    echo "Host: 127.0.0.1"
    echo "Port: 6379"
    echo "Password: $REDIS_PASSWORD"
    echo ""
    print_warning "Please save this password - you'll need it for Pelican Panel configuration"
}

update_panel() {
    print_status "Updating Pelican Panel"
    
    if [[ ! -d "/var/www/pelican" ]]; then
        print_error "Pelican Panel directory not found"
        exit 1
    fi
    
    echo ""
    print_warning "This will update your Pelican Panel to the latest version"
    print_warning "Make sure you have a backup of your panel before proceeding"
    echo -n "Do you want to continue with the update? (y/N): "
    read -r choice < /dev/tty
    
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        print_warning "Panel update cancelled"
        exit 0
    fi
    
    cd /var/www/pelican || {
        print_error "Could not change to panel directory"
        exit 1
    }
    
    print_status "Putting Panel in Maintenance Mode..."
    php artisan down
    print_success "Panel is now in maintenance mode"
    
    print_status "Downloading Update..."
    curl -L https://github.com/pelican-dev/panel/releases/latest/download/panel.tar.gz | tar -xzv
    if [[ $? -eq 0 ]]; then
        print_success "Update files downloaded successfully"
    else
        print_error "Failed to download update files"
        php artisan up
        exit 1
    fi
    
    print_status "Giving Permissions..."
    chmod -R 755 storage/* bootstrap/cache/ 2>/dev/null || true
    print_success "File permissions updated"
    
    print_status "Updating Dependencies..."
    COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --optimize-autoloader
    if [[ $? -eq 0 ]]; then
        print_success "Dependencies updated successfully"
    else
        print_error "Failed to update dependencies"
        php artisan up
        exit 1
    fi
    
    print_status "Creating Storage Links..."
    php artisan storage:link
    print_success "Storage links created"
    
    print_status "Renewing Cache Components..."
    php artisan optimize:clear
    php artisan optimize
    print_success "Cache components renewed"
    
    print_status "Updating Database..."
    php artisan migrate --seed --force
    if [[ $? -eq 0 ]]; then
        print_success "Database updated successfully"
    else
        print_error "Database migration failed"
        php artisan up
        exit 1
    fi
    
    print_status "Setting Permissions for Webserver..."
    chown -R www-data:www-data /var/www/pelican
    print_success "Webserver permissions set"
    
    print_status "Restarting Queue Workers..."
    php artisan queue:restart
    print_success "Queue workers restarted"
    
    print_status "Disabling Maintenance Mode..."
    php artisan up
    print_success "Panel is now live again"
    
    echo ""
    print_success "Panel update completed successfully!"
    print_warning "Please verify that your panel is working correctly"
    print_warning "Check the panel logs if you encounter any issues"
}
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
    
    if [[ $INSTALL_REDIS == true ]]; then
        echo "4. Configure Redis in your .env file using the credentials below"
        echo ""
        print_warning "Redis Configuration:"
        echo "   Host: 127.0.0.1"
        echo "   Port: 6379"
        echo "   Password: $REDIS_PASSWORD"
        echo ""
        print_warning "Redis credentials are also saved in: /var/www/pelican/redis-credentials.txt"
    fi
    
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
    if [[ $INSTALL_REDIS == true ]]; then
        echo "- Secure your Redis installation by limiting network access"
        echo "- Consider configuring Redis with TLS if needed"
    fi
}

main() {
    echo -e "${BLUE}--------PELICAN INSTALLATION SCRIPT--------${NC}"
    echo -e "${GREEN}Made by: Verdanox${NC}"
    echo ""
    
    check_root
    detect_os
    
    if check_pelican_installation; then
        show_management_menu
        exit 0
    fi
    
    print_warning "Installing Pelican Panel on your server..."
    print_warning "Operating System: $OS $VERSION"
    echo ""
    
    ask_redis_installation
    
    install_php
    install_nginx
    create_directories
    install_files
    install_composer
    setup_nginx
    create_env
    set_permissions
    
    install_redis
    
    display_completion
}

main "$@"
