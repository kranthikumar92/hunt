### Огромное спасибо iceland2k14 за его работу

### Ресурсы для проверки работы

  для проверки пользуюсь ресурсами:
  https://iancoleman.io/bip39/  
  https://kriptokurs.ru/bitcointools/tool/hash-to-address    
    
  Описание как это работает :  
  https://learnmeabitcoin.com/technical/derivation-paths  
  
### HUNT to MNEMONIC (HASH160)
Brute Force Bitcoin address и не только Биткоин адресов
Программа создана в первую очередь для изучения языка PYTHON! 

Что реализовано:  
#### создание BIP39 Mnemonic для 10 языков. Возможно использовать все сразу или какие-то отдельно 
-english  
-chinese_simplified  
-chinese_traditional  
-french  
-italian  
-spanish  
-czech  
-korean  
-japanese  
-portuguese  
(список языков редактируйте в файле consts.py)

### Установка в ручную:
    pip install simplebloomfilter  
    pip install bitarray==1.9.2  
    https://github.com/Noname400/mnemonic-for-hunt  
    cd mnemonic-for-hunt  
    python setup.py install  
    Pip install colorama  
    sudo pip3 install bip32   
  
#### Создаем HASH160 из Адресов:  
python addr_to_h160.py <in file> <outfile>
  in file - текстовый файл с адресами (один адрес на одну срочку)  
  out file - файл hash160  
  
#### Создайте BloobFilter (BF create\Cbloom.py)
python create_bloom.py <in file> <outfile>  
  in file - текстовый файл с hash160 (один hash на одну срочку)  
  out file - файл блюм фильтра  
  
### Режимы работы:  
#### Стандартный (-m s):  
#### Случайный (-m r1):  случайным образом генерирует SEED
#### Случайный (-m r2):  случайным образом генерирует Mnemonic

#### Работа со списком слов   
  Сейчас реализовано работа со словами (12,15,18,21,24) (-bit)
  в битах количество слов 128, 160, 192, 224, 256
  например надо искать по 12 словам (-bit 128)
  
### Многопоточная версия  
    python -B PulsarMTv4.py -b 44 -db BF\btc_without_0.bf -th 3 -des source -m s -bit 128 -sl 5 -em no -dbg 0
  
    -b Режим поиска (BIP32, BIP44, ETH)  (-b ETH)
    -db расположение файла ФлюмФильтра (-db BF/work.bf)
    -th количество процесов запущеных для поиска (-th 2)
    -des описание вашей машины. Чаще всего нужно при отправке почты, если нашелся адрес. если у вас работает только одна машина на поиск то параметр можно не указывать
    -m режим формирования мнемоники (случайный -m r1 (r2) , стандартный -m s) выбор за вами . (-m s)
    -bit битность мнемоники (12 слов это 128 бит) смотрите выше "Работа со списком слов" (-bit 128)
    -em контроль отправки электроной почты при нахождении мнемоники (если ненужно поставьте no) (-em no)
    -sl задержка по пуску блюм фильтра (у кого много ядер, рекомендую!)
    -dbg это отладочная информация, при указании данного параметра программа будет показывать что и как она формирует, можно будет проверить по ссылкам выше. режима 2
         Режим 1: вам скорее всего не пригодится так как вы не добавили в свою базу отладочные адреса (если хотите я их вам дам)
         Режим 2: этот режим отображает всю информацию которая генерируется программой. Нужна для того что бы проверить правильно ли генерируются адреса.

    
## Не забудьте настроить параметры своей почты для отправки найденных мнемоник  
    host:str = 'smtp.mail.ru'  
    port:int = 25  
    password:str = 'adfgvfdvbfdsgbdf'  
    to_addr:str = 'info@mail.ru'  
    from_addr:str = 'info@mail.ru'  
  
  
  
файлы с адресами брать здесь  
https://gz.blockchair.com/  
  
или на моем ресурсе:  
https://drive.google.com/drive/folders/1oBMNxqwyYqp6Dx1q5j6erajf9wahGAda?usp=sharing (базы с адресами)
https://drive.google.com/drive/folders/1ILhIERsWHTvQ1-HwgzQLyKm3G7VPzgjY?usp=sharing (готовые блюм фильтры)

----------------------------------------------------------------------
* Version:  * Pulsar v4.6.0 multiT Hash160 *
* Total kernel of CPU: 4
* Used kernel: 3
* Mode Search: BIP-44 Standart
* Database Bloom Filter: BF\btc_without_0.bf
* Languages at work: ['english', 'japanese', 'spanish', 'chinese_simplified']
* Work BIT: 128
* Description client: source
* Smooth start 5 sec
* Send mail: Off
----------------------------------------------------------------------
Mnemonic: 112 | Total keys 3200 | Speed 5581 key/s | Found 0
    

### Благодарность за мою работу:  
Bitcoin: bc1qnnamfvhrms5sldh83tsesmud8erqm95qttuvw5  
Ethereum: 0xAda9515891532dbA75145c27569e7D5704DBe87f  
