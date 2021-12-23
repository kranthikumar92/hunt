#### Огромное спасибо iceland2k14 за его работу

#### Ресурсы для проверки работы
  для проверки пользуюсь ресурсами:
  https://iancoleman.io/bip39/  
  https://kriptokurs.ru/bitcointools/tool/hash-to-address    

  Описание как это работает:
  https://learnmeabitcoin.com/technical/derivation-paths

#### HUNT to MNEMONIC (HASH160)
Brute Force Bitcoin address не только Биткоин адресов
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
        mnemonic_lang:list = ['english','chinese_simplified'] # ['english', 'chinese_simplified', 'chinese_traditional', 'french', 'italian', 'spanish', 'korean','japanese','portuguese','czech']
    Все возможные комбинации мнемоник. если надо больше вложений, аккаунтов и т.д. несложно добавить.
    5 случайных режима
        S - Стандартный режим. Он создает мнемоник согласно спецификации BIP39
        R1 - режим генерации SEED случайным образом, он не зависит от языка
        R2 - режим по генерации мнемоники без подсчета чексуммы
        GAME - это режим для веселухи Ж-) в папке лежит файл game_en.txt в нем 3000 самых используемых английских слов, программа случайным образом выбирает количество слов от 1 до 25 и затем случайно выбирает слова
            вы можете заменить слова на свои.
        CUSTOM - режим для самостоятельных переборов и словарей
    4 варианта поиска (BIP32, BIP44, ETH, BTC)
        - Режим BTC ищет только по BTC но во всех вариациях (BIP32, BIP44, BIP49)
        Режим BIP84 и выше делать не буду, этими кошельками пользуются люди.

#### Установка:
    для установки на windows необходимо установить Microsoft build tools
    установочный файл находится в папке install
    <img> <\img>
    <img> <\img>
    также в папке лежит уже готовый файл конфигурации
    как добавить его на фото выше

    pip install simplebloomfilter
    pip install bitarray==1.9.2
    в папке install лежит инсталятор мнемоники
    pip install mnemonic-0.20-py3-none-any.whl
        если не хотите устонавливать пакет, то добро пожаловать в репозиторий https://github.com/Noname400/mnemonic-for-hunt
    pip install colorama
    pip install bip32
    pip install requests

для установки на windows необходимо установить Microsoft build tools

#### Создаем HASH160 из Адресов:
    создание HASH160 требуется для всех адресов КРОМЕ ETH и ETC. адреса ETH и ETC сразу конверируются в блюм фильтр, без дополнительной конвертиции
    python addr_to_h160.py <in file> <out file>
      in file - текстовый файл с адресами (один адрес на одну срочку)  
      out file - файл hash160  

#### Создайте BloobFilter (BF create\Cbloom.py)
    ПОМНИТЕ: адреса ETH и ETC и прочии производные должны быть без '0x'
        0x0284A72A0fe8fCC4867fbeA622D862E4a28d0DB7 такой адрес не корректен. нужен 0284A72A0fe8fCC4867fbeA622D862E4a28d0DB7
        на сайте https://gz.blockchair.com/ethereum/addresses/ как раз адреса без '0x' и вы можете их преобразовать сразу в блюм
    python create_bloom.py <in file> <out file>  
      in file - текстовый файл с hash160 (один hash на одну срочку)  
      out file - файл блюм фильтра  
  
#### Работа со списком слов   
    Сейчас реализовано работа со словами (3, 6, 9, 12, 15, 18, 21, 24) 
    в битах количество слов 32, 64, 96, 128, 160, 192, 224, 256 (-bit)
    например надо искать по 12 словам (-bit 128)
  
#### Ключи использования  (Проверьте свои БАТНИКИ, аргументы для запуска изменились)
    python -B PulsarMTv4.py -b 44 -db BF\btc_without_0.bf -th 3 -des source -m s -bit 128 -sl 5 -em -bal -dbg 0
  
    -b Режим поиска (BIP32, BIP44, ETH, BTC)  (-b 32,44,ETH,BTC)
    -db расположение файла ФлюмФильтра (-db BF/work.bf)
    -th количество процесов запущеных для поиска (-th 2)
    -des описание вашей машины. Чаще всего нужно при отправке почты, если нашелся адрес. если у вас работает только одна машина на поиск то параметр можно не указывать (-des locale)
    -m режим формирования мнемоники (случайный -m r1,r2,game , стандартный -m s) выбор за вами . (-m s)
    -bit битность мнемоники (12 слов это 128 бит) смотрите выше "Работа со списком слов" (-bit 128)
    -em контроль отправки электроной почты при нахождении мнемоники (-em)
    -sl задержка по пуску блюм фильтра (у кого много ядер, рекомендую!) (-sl 5)
    -bal проверка баланса при нахождении. если балан 0 то рескан не делается (-bal)
    -dbg это отладочная информация, при указании данного параметра программа будет показывать что и как она формирует, можно будет проверить по ссылкам выше. режима 2 (-dbg 0,1,2)
         Режим 1: вам скорее всего не пригодится так как вы не добавили в свою базу отладочные адреса (если хотите я их вам дам)
         Режим 2: этот режим отображает всю информацию которая генерируется программой. Нужна для того что бы проверить правильно ли генерируются адреса.
    Режим пользовательских словарей:
    -m custom выбор режим пользовательского словаря (-m custom)
    -cd путь до пользовательского файла (-cd DB/my.txt)
    -cw количество слов для генерации (-cw 6)
    -cl язык словаря (-cl english) (english,chinese_simplified,chinese_traditional,french,italian,spanish,czech,korean,japanese,portuguese)
    Обычный режим:
    python -B PulsarMTv4.py -b BTC -db BF\btc_without_0.bf -th 1 -des test -m s -bit 128 -sl 5 -dbg 0 -em -bal
    Режим пользователя:
    python -B PulsarMTv4.py -b BTC -db BF\btc_without_0.bf -th 1 -des test -m custom -cd wl\custom.txt -cw 6 -cl english -sl 5 -dbg 0 -em -bal


    
#### Не забудьте настроить параметры своей почты для отправки найденных мнемоник  
    host:str = 'smtp.mail.ru'  
    port:int = 25  
    password:str = 'adfgvfdvbfdsgbdf'  
    to_addr:str = 'info@mail.ru'  
    from_addr:str = 'info@mail.ru'  
  
  
  
файлы с адресами брать здесь  
https://gz.blockchair.com/  
  
или на моем ресурсе:  
https://drive.google.com/drive/folders/1E2rC7GSc59lAIJi_gD0O-tgGiXwcS7Wl?usp=sharing (готовые блюм фильтры)

    E:\GitHub\Hunt-to-Mnemonic>python -B PulsarMTv4.py -b BTC -db BF\export.bf -th 3 -des test -m game -sl 5 -dbg 0 -bal
    ----------------------------------------------------------------------
    Thank you very much: @iceland2k14 for his libraries!
    ----------------------------------------------------------------------
    DEPENDENCY TESTING:
    [I] TEST: OK!
    ----------------------------------------------------------------------
    [I] Version: * Pulsar v4.7.8 multiT Hash160 *
    [I] Total kernel of CPU: 4
    [I] Used kernel: 3
    [I] Mode Search: BIP-BTC Game words
    [I] Database Bloom Filter: BF\export.bf
    [I] Work BIT: 128
    [I] Description client: test
    [I] Smooth start 5 sec
    [I] Send mail: Off
    [I] Check balance BTC: On
    ----------------------------------------------------------------------
    > Mnemonic: 165 | Total keys 237600 | Speed 10409 key/s | Found 0
    [W] Found address | 1BAcuhXVLq7x3Fi8twkWf24jyX5XNjXUqj:0.0 | 1AFifimawizUKRcWsaurJrDnub7SA9TZJZ:0.0 | 3BrdqF1vtjSL8RQa23R75eRg83NEwLfxJA:0.0
    [W] Found address balance 0.0
    > Mnemonic: 813 | Total keys 1170720 | Speed 9652 key/s | Found 0
    [W] Found address | 145XnMUwJ9N682VJeKZH3oZGKuE4LwAHTD:0.0 | 1Mc3xpX3GxJ97fdXbx4qHeYMSixFsPpZew:0.0 | 34mYhtyNr3gUDCBjmRDsURvCURWmvXhWeJ:0.0
    [W] Found address balance 0.0
    > Mnemonic: 903 | Total keys 1300320 | Speed 6256 key/s | Found 0
    

#### Благодарность за мою работу:  
Bitcoin: bc1qnnamfvhrms5sldh83tsesmud8erqm95qttuvw5  
Ethereum: 0xAda9515891532dbA75145c27569e7D5704DBe87f  
