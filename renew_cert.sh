docker run --rm \
    -e AWS_SHARED_CREDENTIALS_FILE=/root/.aws/config \
    -v "$(pwd)/.aws/credentials:/root/.aws/config" \
    -v "$(pwd)/etc/letsencrypt:/etc/letsencrypt" \
    -v "$(pwd)/var/lib/letsencrypt:/var/lib/letsencrypt" \
    certbot/dns-route53 \
    renew \
    --dns-route53
