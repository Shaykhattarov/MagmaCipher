from src.hash import Hash
from src.prng import GeneratorBBS


ENCODING = "UTF-8"



class Magma:
    
    sbox: tuple[tuple[int]] = ((4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3), 
                               (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
                               (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
                               (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
                               (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
                               (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
                               (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
                               (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12))
    
    __key_length: int = 32 # Длина ключа 32 байта = 256 бит
    __block_size: int = 8  # Длина блока 8 байт = 64 бит
    __subkeys: list[int]
    __key: list[int]
    
    seed: str = 'secret'

    def __init__(self):
        self.prng: GeneratorBBS = GeneratorBBS()
        self.hasher: Hash = Hash()

    def encrypt(self, data: str|bytes, password: str) -> str:
        """ Функция инициализации шифрования сообщения """
        data: bytearray = self.__converttexttobytearray(data)
        print('[INFO] Входная байтовая последовательность: ', data, ' - ', len(data))
        self.__key: list[int] = self.__generate_256bit_key(password)   # Генерируем 256 битный ключ из пароля
        self.__subkeys: bytearray = self.__convertsequencetobytearray(self.__key)      # Разбиваем ключ на 8 кусков
        blocks = self.__generate_blocks(data)

        output_buffer: list[str] = []
        for block in blocks: 
            # print('encr blck', block)
            encrytped_block = self.__encrypt_block(block, self.__subkeys)
            output_block: bytes = int.to_bytes(encrytped_block, length=self.__block_size, byteorder='little', signed=False)
            output_buffer.append(output_block.hex())
        return "".join(output_buffer)
    
    def decrypt(self, cipher: str, password: str, datatype: str = 'text') -> str:
        """ Функция инициализации дешифрования сообщения """
        if len(cipher) % self.__block_size != 0:
            raise ValueError("Некорректное зашифрованное сообщение!")

        self.__key: list[int] = self.__generate_256bit_key(password)
        self.__subkeys: bytearray = self.__convertsequencetobytearray(self.__key)
        blocks: bytearray = self.__recovery_blocks(cipher)

        output_buffer: list[str] = []
        for block in blocks:
            decrypted_block: int = self.__decrypt_block(block)
            output_block: bytes = int.to_bytes(decrypted_block, length=self.__block_size, byteorder='little', signed=False)
            output_block.replace(b'\0', b'')
            output_buffer.append(output_block)
        
        if datatype == 'text':
            return b''.join(output_buffer).replace(b'\x00', b'').decode(ENCODING)
        
        return b''.join(output_buffer)

    def __generate_256bit_key(self, password: str):
        pswhash: int = self.hasher.mahash5((self.seed + password))
        return self.prng.generate(pswhash, (self.__key_length * 8))
              
    def __convertsequencetobytearray(self, sequence: list[int]) -> bytearray:
        buffer = ""
        result = bytearray()
        for i in range(len(sequence)):
            buffer += str(sequence[i])
            if len(buffer) % 8 == 0:
                result.append(int(buffer, 2))
                buffer = ""
        return result
    
    def __converttexttobytearray(self, data: str|bytes) -> bytearray:
        if isinstance(data, str): return bytearray(data.encode(ENCODING))
        if isinstance(data, bytes): return bytearray(data)

    def __generate_blocks(self, data: bytearray) -> list[int]:
        blocks: list[int] = []
        block: int = 0
        length: int = len(data)
        for i in range(self.__block_size, length + 1, self.__block_size):
            block = int.from_bytes(data[i - self.__block_size: i], byteorder='little', signed=False)
            blocks.append(block)
        
        if len(data) % self.__block_size != 0:
            remainder = data[length - (length % self.__block_size) : length]
            while (len(remainder) % self.__block_size != 0): remainder.append(0)
            block: int = int.from_bytes(remainder, byteorder='little', signed=False)
            blocks.append(block)
        return blocks
    
    def __recovery_blocks(self, cipher: str) -> list[bytearray]:
        result = []
        buffer: bytearray = bytes.fromhex(cipher)
        for i in range(self.__block_size, len(buffer) + 1, self.__block_size): 
            result.append(buffer[i - self.__block_size : i])

        for i in range(len(result)): 
            result[i] = int.from_bytes(result[i], 'little', signed=False)
            # print('decr blck', result[i])
        return result

    def __crypto_function(self, part: int, key: int) -> int:
        temp = part ^ key # Складываем по модулю
        output = 0
        ###
        # Разбиваем по 4бита
        # В рез-те sbox[i][j] где i-номер шага, j-значение 4-битного куска i шага
        # Выходы всех восьми S-блоков объединяются в 32-битное слово
        for i in range(8):
            output |= ((self.sbox[i][(temp >> (4 * i)) & 0b1111]) << (4 * i)) # всё слово циклически сдвигается влево (к старшим разрядам) на 11 битов.
        return ((output >> 11) | (output << (32 - 11))) & 0xFFFFFFFF
    
    def __encrypt_block(self, block: int, subkeys: bytearray):
        def encrypt_round(left_part, right_part, round_key):
            return right_part, left_part ^ self.__crypto_function(right_part, round_key) 

        left_part = block >> 32
        right_part = block & 0xFFFFFFFF

        ###
        # Выполняем 32 раунда со своим подключом Ki
        # Ключи K1...K24 являются циклическим повторением ключей K1...K8 (нумеруются от младших битов к старшим).
        for i in range(24):
            left_part, right_part = encrypt_round(left_part, right_part, subkeys[i % 8])
        ###
        # Ключи K25...K32 являются ключами K1...K8, идущими в обратном порядке.
        for i in range(8):
            left_part, right_part = encrypt_round(left_part, right_part, subkeys[7 - i])

        return (left_part << 32) | right_part # Сливаем половинки вместе


    def __decrypt_block(self, block: int):
        def decrypt_block(left_part, right_part, round_key):
            return right_part ^ self.__crypto_function(left_part, round_key), left_part
        
        left_part = block >> 32
        right_part = block & 0xFFFFFFFF

        for i in range(8):
            left_part, right_part = decrypt_block(left_part, right_part, self.__subkeys[i])
        
        for i in range(24):
            left_part, right_part = decrypt_block(left_part, right_part, self.__subkeys[(7 - i) % 8])

        return (left_part << 32) | right_part
            