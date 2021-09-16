### Выложил Бэту версии 4. (смотрите батники)

## NEWS:
  
  Добавлен ZCASH  
  перезалил базы на гугл

# ОПИСАНИЕ В ПРОЦЕССЕ !!!!  
  
  для проверки пользуюсь ресурсами:  
  https://iancoleman.io/bip39/  
  https://www.indicrypto.com/bitcointools/  
  
  Описание как это работает :  
  https://learnmeabitcoin.com/technical/derivation-paths
  
# HUNT to MNEMONIC (HASH160)
Brute Force Bitcoin address
Программа создана в первую очередь для изучения языка PYTHON! 

В чем разница от первой версии?  
в этой версии ведется поиск по HASH160, то есть мы убираем одно конвертирование (hash160 в адрес)  
это позволяет объединить все в один файл, так как хеш одинаковый
так же добавлен поиск ключей в несжатом формате

### Смотрите бонус внизу описания!  

Что реализовано:  
#### создание BIP39 Mnemonic для 9 языков. Возможно использовать все сразу или какие-то отдельно 
english, chinese_simplified, chinese_traditional, french, italian, spanish, czech, korean, japanese (список языков редактируйте в файле)  
  
#### Планы:  
[ ] Клиент-сервер  
[ ]  WEB Сервер статистики  
[Х] Добавить поиск по ETH, ETC  
[ ] оформить описание ;-)  
  


## Установка в ручную:  
    Зависимости: Python 3.6 и выше  
    sudo pip3 install simplebloomfilter  
    sudo pip3 install bitarray==1.9.2  
    Убрано sudo pip3 install mnemonic  (использовать из моего репозитория)   
    https://github.com/Noname400/python-mnemonic  
    убрано sudo pip3 install bip-utils==1.11.1  (использовать из моего репозитория)   
    https://github.com/Noname400/bip-utils   
    sudo pip3 install bip32   
    sudo pip3 install coincurve   
  
## Установка автоматом  
pip install -r requirements.txt  
или  
python -m pip install -r requirements.txt

Создаем HASH160 из Адресов:  
python h160.py <in file> <outfile>
  in file - текстовый файл с адресами (один адрес на одну срочку)  
  out file - файл hash160  
  
создайте BloobFilter (BF create\Cbloom.py)
python Cbloom.py <in file> <outfile>  
  in file - текстовый файл с hash160 (один hash на одну срочку)  
  out file - файл блюм фильтра  
  
## Добавлен режим работы  
#### Стандартный (-m s):  
#### Случайный (-m r):  

#### Работа со списком слов
  Сейчас реализовано работа со словами (3,6,9,12,15,18,21,24) (-bit)
  в битах количество слов 32, 64, 96, 128, 160, 192, 224, 256
  например надо искать по 6 словам (-bit 96)
  
## Многопоточная версия  
  python mainMT.py -b <BIP 32 или 44> -d <директория с файлами блюм фильтра> -t <количество ядер> -m <режим работы> -w <сколько слов 12 или 24> -c <описание сервера> -e (дебаг без аргумента) 
  python mainMT.py -b 32 -d BF -t 2 -m s -w 12 -c Local_win  
  python mainMT.py -b 44 -d BF -t 3 -m r -w 24 -c Local_win  
  python mainMT.py -b ETH -d BF -t 2 -m s -w 12 -c Local_win  

    
## Не забудьте настроить параметры своей почты для отправки найденных мнемоник  
    host:str = 'smtp.mail.ru'  
    port:int = 25  
    password:str = 'adfgvfdvbfdsgbdf'  
    to_addr:str = 'info@mail.ru'  
    from_addr:str = 'info@mail.ru'  
  
  
  
файлы с адресами брать здесь  
https://gz.blockchair.com/  
  
или на моем ресурсе  
Скоро выложу...

  

    * Version:  * Pulsar v3.8.4 multiT Hash160 BETA*
    * Identificator system: b'00000000-0000-0000-0000-74d435f6fa48'
    * Total kernel of CPU: 4
    * Used kernel: 2
    * Mode Search: BIP-44 Standart
    * Dir database Bloom Filter: bf
    * Languages at work: ['english']
    * Description Server: work
    * Mode debug: Off
    * Send mail: On
    * Send Statistic to server: Off
    * Bloom Filter 44.bf Loaded.
    * Bloom Filter 44.bf Loaded.
    * File address pazzle BTC~30 Loaded.
    * File address pazzle BTC~30 Loaded.
    [*] Mnemonic: 6 | Total keys 6720 | Speed 2345 key/s | Found 0
    

### БОНУС!  
  на облачных серверах ORACLE можно арендовать БЕСПЛАТНО 2 сервера навсегда. Скорось там не большая но для тестов хватит.

### Благодарность за мою работу:  
Bitcoin: bc1qnnamfvhrms5sldh83tsesmud8erqm95qttuvw5  
Ethereum: 0xAda9515891532dbA75145c27569e7D5704DBe87f  
