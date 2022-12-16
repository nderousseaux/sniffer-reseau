# Sniffer réseau

## Lancement
```bash
## Docker (with dhcpd)
docker-compose up -d
docker-compose exec analyzer bash -c 'make && ./analyzer [-i interface] [-o fichier] [-f filtre] [-v niveau]'

## Debian
make && ./analyzer [-i interface] [-o fichier] [-f filtre] [-v niveau]
```

## Documentation
Le fichier main.c contient la boucle principale du programme : la fonction `compute-packet` est appelée à chaque réception de paquet.
Il va :
- Créer une structure pck, qui contient le paquet et ses informations
- Appeler la fonction compute_pck, qui va remplir la structure pck avec les informations du paquet.
- Appeler la fonction print_pck, qui va afficher les informations du paquet.

### Fonction compute_pck
La fonction compute_pck va appeler les fonctions compute de chaque couche, afin de remplir la structure pck.
Elle commencera par appeler compute_link, puis compute_network, puis compute_transport, puis compute_application.

Ensuite, chaque fonction compute va procéder de la même manière :
- Déterminer le type de la couche, avec la fonction `determine_type` (ARP/IPv4/IPv6 pour la couche réseau par exemple)
- Appeler la fonction `compute_` suivi du type de la couche (compute_arp, compute_ipv4, compute_ipv6, etc.)
- Mettre à jour le log de la couche avec la fonction `set_log`

De manière similaire, la chaque fonction compute propre à chaque protocole va procéder de la même manière :
- Remplir une structure de données servant à stocker les informations du paquet (compute_ether remplira une structure ether_header)
- Remplir ensuite les logs de la couche avec la fonction `set_log`.

### Affichage des logs
Une fois que le paquet est traité, on l'affiche.
Le dossiers `logs` contient les fonctions pour afficher les logs.
`v1.c`, `v2.c`, et `v3.c` permettent d'afficher les logs de différentes manières.
Ils ont tout les trois au moins ces trois fonctions -> `init`, `print`, `end`.
`init` est appelé au début de l'analyse, `print` est appelé à chaque paquet, et `end` est appelé à la fin de l'analyse.

Ces fonctions vont parcourir la structure pck remplie lors de l'analyse et afficher les informations.


## Arborecence des protocoles

|-Ethernet                  --> Implémenté
| |-ARP                     --> Implémenté
| |-IPV6                    --> Implémenté
| |-IPV4                    --> Implémenté
| | |-UDP                   --> Implémenté
| | | |-BOOTP               --> Implémenté
| | | | |-DHCP              --> Implémenté
| | | |-DNS                 --> Sur l'autre projet
| | |-TCP                   --> Implémenté
| | | |-telnet              --> Sur l'autre projet
| | | |-FTP                 --> Sur l'autre projet
| | | |-POP                 --> Sur l'autre projet
| | | |-IMAP                --> Sur l'autre projet
| | | |-SMTP                --> Sur l'autre projet    
| | | |-HTTP                --> Sur l'autre projet
| | | |-DNS                 --> TODO
| | |-ICMP                  --> Implémenté