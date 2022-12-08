# Sniffer réseau

## Lancement
```bash
## Docker (with dhcpd)
docker-compose up -d
docker-compose exec analyzer bash -c 'make && ./analyzer [-i interface] [-o fichier] [-f filtre] [-v niveau]'

## Debian
make && ./analyzer [-i interface] [-o fichier] [-f filtre] [-v niveau]
```

## Arborecence des protocoles

|-Ethernet                  --> Implémenté v1
| |-ARP                     --> Implémenté v1
| |-IPV6                    
| |-IPV4                    --> Implémenté v1
| | |-UDP                   --> Implémenté v1
| | | |-BOOTP               --> Implémenté v1
| | | | |-DHCP              --> Implémenté v1
| | | |-DNS                 --> Implémenté v1
| | |-TCP                   --> Implémenté v1
| | | |-telnet              --> Implémenté v1
| | | |-FTP                 --> Implémenté v1
| | | |-POP                 --> Implémenté v1
| | | |-IMAP
| | | |-SMTP           
| | | |-HTTP
| | | |-HTTPS
| | | |-DNS
| | |-ICMP                  --> Implémenté v1