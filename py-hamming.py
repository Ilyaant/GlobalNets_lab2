# БПМ-19-2, Антонов Илья, вариант 3
# Основа кода для реализации кода Хэмминга взята из https://gist.github.com/baskiton/6d361f4155f41e91c4be1dce897f7431
# -*- coding: utf-8 -*-

from typing import List
from math import log2, ceil
from random import randrange
from crc64iso.crc64iso import crc64


def __hamming_common(src: List[List[int]], s_num: int, encode=True) -> int:
    s_range = range(s_num)
    errors = 0

    for i in src:
        sindrome = 0
        for s in s_range:
            sind = 0
            for p in range(2 ** s, len(i) + 1, 2 ** (s + 1)):
                for j in range(2 ** s):
                    if (p + j) > len(i):
                        break
                    sind ^= i[p + j - 1]

            if encode:
                i[2 ** s - 1] = sind
            else:
                sindrome += (2 ** s * sind)

        if (not encode) and sindrome:
            try:
                i[sindrome - 1] = int(not i[sindrome - 1])
            except IndexError:
                errors += 1

    return errors


def hamming_encode(msg: str, mode: int = 8) -> str:
    """
    Encoding the message with Hamming code.

    :param msg: Message string to encode
    :param mode: number of significant bits
    :return: 
    """

    result = ""

    # msg_b = msg.encode("utf-8")
    msg_b = msg.encode("utf8")
    s_num = ceil(log2(log2(mode + 1) + mode + 1))   # number of control bits
    bit_seq = []
    for byte in msg_b:  # get bytes to binary values; every bits store to sublist
        bit_seq += list(map(int, f"{byte:08b}"))

    res_len = ceil((len(msg_b) * 8) / mode)     # length of result (bytes)
    bit_seq += [0] * (res_len * mode - len(bit_seq))    # filling zeros

    to_hamming = []

    for i in range(res_len):    # insert control bits into specified positions
        code = bit_seq[i * mode:i * mode + mode]
        for j in range(s_num):
            code.insert(2 ** j - 1, 0)
        to_hamming.append(code)

    errors = __hamming_common(to_hamming, s_num, True)   # process

    for i in to_hamming:
        result += "".join(map(str, i))

    return result


def hamming_decode(msg: str, mode: int = 8):
    """
    Decoding the message with Hamming code.

    :param msg: Message string to decode
    :param mode: number of significant bits
    :return: 
    """

    result = ""

    s_num = ceil(log2(log2(mode + 1) + mode + 1))   # number of control bits
    res_len = len(msg) // (mode + s_num)    # length of result (bytes)
    code_len = mode + s_num     # length of one code sequence

    to_hamming = []

    for i in range(res_len):    # convert binary-like string to int-list
        code = list(map(int, msg[i * code_len:i * code_len + code_len]))
        to_hamming.append(code)

    errors = __hamming_common(to_hamming, s_num, False)  # process

    for i in to_hamming:    # delete control bits
        for j in range(s_num):
            i.pop(2 ** j - 1 - j)
        result += "".join(map(str, i))

    msg_l = []

    for i in range(len(result) // 8):   # convert from binary-sring value to integer
        val = "".join(result[i * 8:i * 8 + 8])
        msg_l.append(int(val, 2))

    # finally decode to a regular string
    try:
        result = bytes(msg_l).decode("utf-8")
    except UnicodeDecodeError:
        pass

    return result, errors


def noizer(msg: str, mode: int) -> str:
    """
    Generates an error in each element of a Hamming encoded message
    """
    seq = list(map(int, msg))
    s_num = ceil(log2(log2(mode + 1) + mode + 1))  # количество служебных битов
    code_len = mode + s_num  # длина кодового слова
    cnt = len(msg) // code_len
    result = ""

    for i in range(cnt):
        to_noize = seq[i * code_len:i * code_len + code_len]
        noize = randrange(code_len)
        to_noize[noize] = int(not to_noize[noize])
        result += "".join(map(str, to_noize))

    return result


def noizer4(msg: str, mode: int) -> str:
    """
    Generates up to 4 errors in each element of a Hamming encoded message
    """
    seq = list(map(int, msg))
    s_num = ceil(log2(log2(mode + 1) + mode + 1))  # количество служебных битов
    code_len = mode + s_num  # длина кодового слова
    cnt = len(msg) // code_len
    result = ""

    for i in range(cnt):
        to_noize = seq[i * code_len:i * code_len + code_len]
        noize1 = randrange(code_len)
        noize2 = randrange(code_len)
        noize3 = randrange(code_len)
        noize4 = randrange(code_len)
        to_noize[noize1] = int(not to_noize[noize1])
        to_noize[noize2] = int(not to_noize[noize2])
        to_noize[noize3] = int(not to_noize[noize3])
        to_noize[noize4] = int(not to_noize[noize4])
        result += "".join(map(str, to_noize))

    return result


if __name__ == '__main__':
    MODE = 29  # длина слова с контрольными битами составляет 35 => значащих битов в слове 29
    msg = 'Программно-конфигурируемая архитектура сетей начинает все больше распространяться в последнее время, поскольку имеет весомые преимущества по сравнению с традиционной: она позволяет повысить управляемость сети (благодаря централизации управления), снизить затраты на эксплуатацию сетевого оборудования, увеличить уровень защищенности сети, а также предоставляет возможность оперативного создания и загрузки новых сервисов в сетевые устройства.\n\nАктуальность противодействия сетевым атакам повышается с каждым днем ввиду все большего распространения сетей (в том числе, программно-конфигурируемых). Для этого используются системы обнаружения вторжений (СОВ, IDS). В данной работе рассматриваются IDS, ядром которых являются методы машинного обучения; в этом случае задача обнаружения вторжений представляет собой задачу классификации сетевого трафика. Такие СОВ способны к самообучению, а также могут работать при относительно небольших мощностях с достаточной скоростью, в отличие от классических IDS.\n\nОсновная особенность программно-конфигурируемой сети (ПКС, SDN) заключается в том, что управление всей сетью выносится на отдельный централизованный вычислительный ресурс - контроллер. Это приводит к следующим преимуществам:\nСеть становится легче изменять и обновлять, что снижает количество человеческих ошибок.\nИТ-администраторы могут легко добавлять сетевые устройства или модернизировать инфраструктуру сети, не привязываясь к конкретному поставщику оборудования.\nНизкоуровневые инфраструктурные устройства не требуют отдельного программирования, что снижает эксплуатационные расходы по сравнению с обычной сетью.\n\nОднако, эта особенность SDN делает контроллер одной из основных целей сетевых атак. Целью данной работы являлось создание и сравнение моделей машинного обучения для обнаружения вторжений в сетях SDN. В ходе работы было создано и протестировано 4 модели машинного обучения (Random Forest, Decision Tree, k-NN и Logistic Regression) и 3 нейросетевых модели (MLP, CNN и LSTM). Для трех моделей был проведен подбор гиперпараметров, что позволило добиться улучшения их работы. Был проведен сравнительный анализ результатов, и лучшей моделью оказалась модель Random Forest с показателями accuracy и F1-меры 0,985 и 0,855 соответственно на датасете InSDN (2020 г.).\n\nТем не менее, при разработке ядра СОВ на основе машинного обучения следует обратить особое внимание на современные методы, в частности, глубокие и рекуррентные нейронные сети.'
    print(f'Сообщение:\n{msg}')
    checksum = crc64(msg)
    print(f'Контрольная сумма: {checksum}')

    # Первая отправка (без ошибок)
    print('-----------ПЕРВАЯ ОТПРАВКА-----------')
    enc_msg = hamming_encode(msg, MODE)
    print(f'Кодированное сообщение:\n{enc_msg}')
    dec_msg, err = hamming_decode(enc_msg, MODE)
    dec_msg = dec_msg[:-2:]
    print(f'Раскодированное сообщение:\n{dec_msg}')
    print(
        f'Контрольная сумма: {crc64(dec_msg)}, корректность: {crc64(dec_msg) == checksum}')
    print(f'MSG: {msg == dec_msg}')

    # Вторая отправка (не более 1 ошибки на слово)
    print('-----------ВТОРАЯ ОТПРАВКА-----------')
    noize_msg = noizer(enc_msg, MODE)
    print(f'Кодированное сообщение с ошибками:\n{noize_msg}')
    dec_msg, err = hamming_decode(noize_msg, MODE)
    dec_msg = dec_msg[:-2:]
    print(f'Раскодированное сообщение:\n{dec_msg}')
    print(
        f'Контрольная сумма: {crc64(dec_msg)}, корректность: {crc64(dec_msg) == checksum}')
    print(f'MSG: {msg == dec_msg}')

    # Третья отправка (4 ошибки на слово)
    print('-----------ТРЕТЬЯ ОТПРАВКА-----------')
    noize_msg = noizer4(enc_msg, MODE)
    print(f'Кодированное сообщение с ошибками:\n{noize_msg}')
    dec_msg, err = hamming_decode(noize_msg, MODE)
    dec_msg = dec_msg[:-2:]
    print(f'Раскодированное сообщение:\n{dec_msg}')
    print(
        f'Контрольная сумма: {crc64(dec_msg)}, корректность: {crc64(dec_msg) == checksum}, количество обнаруженных ошибок: {err}')
