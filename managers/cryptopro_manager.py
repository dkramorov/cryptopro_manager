import datetime
import os
import re
import time

from managers.simple_logger import logger, json_pretty_print
from managers.system_manager import search_binary, system_cmd
from managers.datetime_manager import str_to_date


class MockSettings:
    FULL_SETTINGS_SET = os.environ


try:
    from django.conf import settings
    hasattr(settings, 'DEBUG')
except Exception as e:
    logger.info('Exception from django.conf import settings: %s' % e)
    settings = MockSettings()


rega_error_code = re.compile(r'\[ErrorCode:(.+)?\]', re.I+re.U+re.DOTALL)
rega_inn = re.compile(r'ИНН[ ЮЛ]*=([0-9]{9,14})', re.I+re.U+re.DOTALL)
rega_spaces = re.compile('[ ]+', re.U+re.I+re.DOTALL)


class CryptoproManager:
    """Работа с Cryptopro
       https://www.cryptopro.ru/sites/default/files/products/cryptcp/cryptcp_5.0.x.pdf
       https://www.cryptopro.ru/sites/default/files/docs/certmgr.pdf
       # Можно установить сертификаты УЦ
       https://support.cryptopro.ru/index.php?/Knowledgebase/Article/View/407/0/oshibk-ne-udetsja-postroit-cepochku-sertifiktov-dlja-doverennogo-kornevogo-centr-0x800b010a
       Файл с основными корневыми сертификатами root.p7b (9kb)
       ./certmgr -install -cert -store uRoot -file root.p7b -all
           Не удалось добавить 1-й сертификат в хранилище
           Отказано в доступе.
       # Установка тестовых сертификатов не помогла для
         Один из сертификатов в цепочке не имеет доверенного корневого ЦС
       ./certmgr -install -cert -store uMy -file root.p7b -all # в uMy встало
       test.p7b - https://www.cryptopro.ru/certsrv/certcarc.asp тестовые сертификаты
       http://testgost2012.cryptopro.ru/CertEnroll/testroot.p7b
    """
    bin_folder = '/opt/cprocsp/bin/'
    media_root = getattr(settings, 'MEDIA_ROOT') if hasattr(settings, 'MEDIA_ROOT') else '/tmp'
    root_folder = os.path.join(media_root, 'cryptopro')
    signed_folder = os.path.join(root_folder, 'signed')
    unsigned_folder = os.path.join(root_folder, 'unsigned')
    crypted_folder = os.path.join(root_folder, 'crypted')
    cryptcp = 'cryptcp'
    certmgr = 'certmgr'
    cryptcp = 'cryptcp'
    csptest = 'csptest'

    def __init__(self, bin_folder: str = None):
        """Подготовка к работе
           Ищем корневую папку, куда установлена cryptopro
           Останавливаем работу, если cryptcp не найден
        """
        system_cmd('mkdir -p %s' % self.signed_folder)
        system_cmd('mkdir -p %s' % self.unsigned_folder)
        system_cmd('mkdir -p %s' % self.crypted_folder)
        if bin_folder:
            self.bin_folder = bin_folder
        else:
            cryptcp = search_binary('cryptcp')
            if cryptcp:
                self.bin_folder = os.path.dirname(os.path.abspath(mc))
        if not cryptcp and os.path.exists('/opt/cprocsp/bin/amd64'):
            self.bin_folder = '/opt/cprocsp/bin/amd64'
        self.cryptcp = os.path.join(self.bin_folder, self.cryptcp)
        self.certmgr = os.path.join(self.bin_folder, self.certmgr)
        self.cryptcp = os.path.join(self.bin_folder, self.cryptcp)
        self.csptest = os.path.join(self.bin_folder, self.csptest)
        assert os.path.exists(self.cryptcp)
        assert os.path.exists(self.certmgr)
        assert os.path.exists(self.cryptcp)
        assert os.path.exists(self.csptest)

    def is_error(self, error_code: str):
        """Проверка, что error_code != 0x00000000
           :param error_code: код ошибки
        """
        return error_code != '0x00000000'

    def get_error_code(self, resp: str):
        """Получить код ошибки (результат работы)
           Успешное выполнение: 0x00000000
           :param resp: полученный ответ выполнения команды
        """
        result = rega_error_code.search(resp)
        if result:
            groups = result.groups()
            return groups[0].strip()

    def show_certs(self, sig_path: str = None):
        """Показывает установленные сертификаты
           Показывает сертификаты из подписанного файла
           :param sig_path: путь к подписанному файлу или самому сертификату (.cer)
        """
        cmd = '%s -list' % self.certmgr
        if sig_path:
            cmd += ' -f %s' % sig_path
        return system_cmd(cmd)

    def sign(self,
             cert_thumbprint: str,
             path: str,
             timeout: int = 10):
        """Подписать файл
           :param cert_thumbprint: отпечаток сертификата
           :param path: путь к файлу, который хотим подписать
        """
        fname = path.split('/')[-1]
        dest = os.path.join(self.signed_folder, '%s.sgn' % fname)
        cmd = '%s -sign -thumbprint %s %s %s' % (
            self.cryptcp,
            cert_thumbprint,
            path,
            dest,
        )
        # Добавление таймаута на команду (если найдено несколько сертификатов и запрашивается ввод)
        cmd = 'timeout %s %s' % (timeout, cmd)
        result = system_cmd(cmd)
        logger.info('\n---\nCryptoproManager [sign] %s\n%s\n---' % (path, result))
        err = self.get_error_code(result)
        logger.info('[ERROR CODE]: %s' % err)
        return dest

    def check_sign(self,
                   path: str,
                   cert_thumbprint: str = None,
                   out: str = None,
                   timeout: int = 10):
        """Проверка подписанного файла
           /opt/cprocsp/bin/cryptcp -verify -thumbprint 94984d6cc5df77db6f63d47a5323cc86390bf46e /Users/jocker/BANKON/bn24_new/bankon/media/cryptopro/signed/test.txt.sgn
           -f использовать сообщение или файл сертификата
           /opt/cprocsp/bin/cryptcp -verify -f /Users/jocker/BANKON/bn24_new/bankon/media/cryptopro/signed/test.txt.sgn /Users/jocker/BANKON/bn24_new/bankon/media/cryptopro/signed/test.txt.sgn
           с выходным файлом:
           /opt/cprocsp/bin/cryptcp -verify -f /Users/jocker/BANKON/bn24_new/bankon/media/cryptopro/signed/test.txt.sgn /Users/jocker/BANKON/bn24_new/bankon/media/cryptopro/signed/test.txt.sgn /tmp/test.txt
           :param path: путь к файлу, который хотим проверить
           :param cert_thumbprint: отпечаток сертификата, которым проверяем
                                   если его нет, используем -f (в подписанном файле сертификат)
           :param out: выходной файл
        """
        verify_by = ('-thumbprint %s' % cert_thumbprint) if cert_thumbprint else ''
        if not verify_by:
            verify_by = '-f %s' % path
        cmd = '%s -verify -nochain %s %s %s' % (
            self.cryptcp,
            verify_by,
            path,
            out if out else '',
        )
        # Добавление таймаута на команду (если найдено несколько сертификатов и запрашивается ввод)
        cmd = 'timeout %s %s' % (timeout, cmd)
        result = system_cmd(cmd)
        logger.info('\n---\nCryptoproManager [check_sign] %s\n%s\n---' % (path, result))
        err = self.get_error_code(result)
        logger.info('[ERROR CODE]: %s' % err)
        return result

    def export_cert(self, sig_path: str, cert_dst: str = None):
        """Получение сертификата из подписанного файла
           TODO: обновить название сертификата после экспорта
           :param sig_path: путь к подписанному файлу
        """
        if not cert_dst:
            cert_folder = os.path.join(self.root_folder, 'certs')
            system_cmd('mkdir -p %s' % cert_folder)
            cert_dst = os.path.join(cert_folder, 'exported.cer')
        cmd = '%s -copycert -der -nochain -norev -f %s -df %s' % (
            self.cryptcp,
            sig_path,
            cert_dst,
        )
        result = system_cmd(cmd)
        logger.info('\n---\nCryptoproManager [export_cert] %s\n%s\n---' % (sig_path, result))
        err_code = self.get_error_code(result)
        logger.info('[ERROR CODE]: %s' % err_code)
        if not self.is_error(err_code):
            return cert_dst

    def parse_cert(self, cert_path: str):
        """Разбор данных по сертификату
           :param cert_path: путь к сертификату
           TODO: несколько сертификатов в одном - распарсить
        """
        certs = []
        keys_mapping = {
            'Issuer': 'Издатель',
            'Subject': 'Субъект',
            'Serial': 'Серийный номер',
            'SHA1 Thumbprint': 'SHA1 отпечаток',
            'SubjKeyID': 'Идентификатор ключа',
            'Signature Algorithm': 'Алгоритм подписи',
            'PublicKey Algorithm': 'Алгоритм откр. кл.',
            'Not valid before': 'Выдан',
            'Not valid after': 'Истекает',
            'OCSP URL': 'OCSP URL',
            'CA cert URL': 'URL списка отзыва',
        }
        keys = list(keys_mapping.keys())
        values = list(keys_mapping.values())

        cert_number = 1
        cert_info = self.show_certs(sig_path=cert_path)
        err_code = self.get_error_code(cert_info)
        if self.is_error(err_code):
            assert False
        cert_info = cert_info.split('\n')
        cert = {}
        for item in cert_info:
            # Если нашелся следующий сертификат, то текущий добавляем в список
            if item.startswith('%s-----' % cert_number):
                cert_number += 1
                certs.append(cert)
                cert = {}
            if not ':' in item:
                continue
            key, value = item.split(':', 1)
            key = key.replace('"', '').strip()

            if not key in keys and not key in values:
                continue
            if key in values:
                key = keys[values.index(key)]
            if value.endswith('",'):
                value = value[:-2]
            cert[key] = value.strip()
            if key in ('Not valid before', 'Not valid after'):
                cert[key] = rega_spaces.sub(' ', cert[key])
                cert[key] = str_to_date(cert[key])
            elif key in ('Subject'):
                search_inn = rega_inn.search(cert[key])
                if search_inn:
                    cert['inn'] = search_inn.group(1)
        if cert:
            certs.append(cert)
        #print(json_pretty_print(certs))
        for cert in certs:
            if cert.get('OCSP URL'):
                return cert

    def crypt(self, cert_path: str, src_path: str, dst_path: str = None):
        """Зашифровать файл
           :param cert_path: путь к сертификату
           :param src_path: путь к файлу для шифрования
           :param dst_path: путь к выходному зашифрованному файлу
        """
        if not dst_path:
            dst_path = '%s.enc' % src_path
        cmd = '%s -encr -nochain -f %s %s %s' % (
            self.cryptcp,
            cert_path,
            src_path,
            dst_path,
        )
        result = system_cmd(cmd)
        logger.info('\n---\nCryptoproManager [crypt] %s\n%s\n---' % (src_path, result))
        err_code = self.get_error_code(result)
        logger.info('[ERROR CODE]: %s' % err_code)
        if not self.is_error(err_code):
            return dst_path

# расшифровка зашифрованного файла (из сервиса)
#/opt/cprocsp/bin/amd64/cryptcp -decr BASE05_07.xlsx.enc BASE05_07.xlsx
