# zderzacz-BTC
Zabawa w szukanie kolizji

Tested in python 3.6.8
Potrzebne dodatkowe moduły ecdsa, base58, requests
Done by Atari_XE ( wypok AD 2019)

Program generuje dowolną ilość kluczy prywatnych oraz przekształca je w opcjonalnie w adresy Legacy bądź SegWit.
Następnie odpytuje blockstream.info i oblicza saldo danego konta.
To tylko zabawa szansa na to że trafi się na tzw kolizję jest więcej niż mała.

Kod jest zlepkiem kilku rozwiązań. Mój wkład jest niewielki. Jest sporo do optymalizacji.
 
Generowanie Bech32 zostało zajebane z tutoriala umieszczonego na YouTube przez Shlomi Zeltsinger.
Który wykorzysuje kod napisany przez Pietera Wuille. Jednego z głównych devów Bitcoin core/ Blockstream.
Kod generujący adress legacy został zajebany z Reddit od usera nykee-J.

(https://github.com/sipa/bech32/tree/master/ref/python)
(https://github.com/zeltsi/segwit_tutorial/tree/master/addresses)
(https://www.youtube.com/channel/UCi9Mf3veSDDIMdGGtPmPu1g)
(https://www.reddit.com/r/Bitcoin/comments/7tzq3w/generate_your_own_private_key_5_lines_of_python/)
(https://github.com/blockstream/esplora/blob/master/API.md)
 
