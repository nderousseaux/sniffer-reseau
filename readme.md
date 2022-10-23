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


|-Ethernet              --> Implémenté
| |-ARP
| |-IPV4                --> Implémenté 
| |-UDP                 --> Implémenté
| | |-BOOTP             --> Implémenté
| | | |-DHCP            --> Implémenté
| |-TCP
| |-ICMP
|- IPV6

