
ENCODING = "UTF-8"


class Scrembler:

    BLOCK_SIZE = 6  # Размер блока
    blocks: list[bytearray]

    def __init__(self):
        pass

    def encrypt(self, data: str|bytes, password: str) -> str:
        data: bytearray = self.__convertdatatobytearray(data)   # Подготавливаем данные, преобразуем их в единый тип bytearray
        self.blocks = self.__arrange_into_blocks(data)
        print(self.blocks)


    def decrypt(self, cipher: str, password: str) -> str:
        pass
    
    def __shift_blocks(self, blocks: list[int], count: int, shift: str='lshift'):
        pass

    def __arrange_into_blocks(self, data: bytearray, block_size=BLOCK_SIZE) -> list[int]:
        buffer = []
        blocks: list[bytearray] = []
        for i in range(len(data)):
            buffer.append(data[i])
            if len(buffer) % block_size == 0 and len(buffer) != 0:
                blocks.append(buffer) 
                buffer = []

        if len(buffer) != 0 and len(buffer) % block_size != 0:
            while len(buffer) != block_size:
                buffer.append(0)
            blocks.append(buffer)

        return blocks
    


    def __convertdatatobytearray(self, data: str|bytes) -> bytearray:
        if isinstance(data, str): return bytearray(data.encode(ENCODING))
        if isinstance(data, bytes): return bytearray(data)

    def __pack(self, block: int):
        bitblock: str = [int(el) for el in bin(block)[1:]]
        print(bitblock)
        for i in range(len(bitblock)):
            pass


scr = Scrembler()
scr.encrypt("Hello world", "Password")