import math


class Generator:

    sequence: list[int] = []
    length: int

    def generate(self) -> list[int]: return

    def unload(self, filename=None) -> None:
        if filename is None:
            raise ValueError("На вход передано пустое значение имени файла")
        if self.sequence is None or len(self.sequence) == 0:
            raise ValueError("На вход переданы пустые данные")
        
        with open(filename, 'w+', encoding='UTF-8') as file:
            file.write("".join([str(el) for el in self.sequence]))


class GeneratorParkMiller(Generator):
    
    m: int = math.pow(2, 31) - 1
    a: int = math.pow(7, 5)

    def generate(self, length=1000) -> list[int]:
        if length is not None and length >= 1000:
            self.length: int = length
        else:
            raise ValueError("Длина генерируемой последовательности в битах должна быть не менее 10.000 бит")
        
        buffer: int = 1
        sequence: list[int] = []
        for i in range(length + 1):
            sequence.append(int((self.a * buffer) % self.m))
            buffer: int = sequence[i]
        sequence.pop(0) # первое число всегда равно 16807        
        self.sequence = [(el % 2) for el in sequence] # берем младший бит числа и заменяем на него само число

        return self.sequence 
        
    
class GeneratorBBS(Generator):

    N: int

    def generate(self, start, length=None) -> list[int]:
        if length is None or length <= 1:
            raise ValueError("Длина генерируемой последовательности бит должна быть не менее 1 бит")
        
        sequence: list[int] = []
        u0 = self.__get_iteration_start_number(start)
        buffer: int = u0
        for i in range(1, length + 1):
            u: int = math.pow(buffer, 2) % self.N
            sequence.append(int(u % 2))
            buffer = u
        return sequence

    def __get_iteration_start_number(self, start_number: int): 
        """ Вычисляем первое итеративное число """
        p = self.__generate_big_simple_number()
        q = self.__generate_big_simple_number()
        self.N = p * q
        # print(p, " * ", q, " = ", self.N, " | ", start_number,  " % ", self.N, " = ", start_number % self.N)
        while not self.__check_mutual_simplicity(start_number, self.N):
            p = self.__generate_big_simple_number()
            q = self.__generate_big_simple_number()
            self.N = p * q
            # print(p, " * ", q, " = ", self.N, " | ", start_number,  " % ", self.N, " = ", start_number % self.N)
        return int(math.pow(start_number, 2) % self.N)  

    def __check_mutual_simplicity(self, num1: int, num2: int) -> bool:
        """ Проверка на взаимную простоту двух чисел (Алгоритм Евклида) """
        a: int = min(num1, num2)
        b: int = max(num1, num2)
        r: int = a % b
        flag: bool = False
        while r > 0:
            a = b 
            b = r
            r = a % b
            if r == 1:
                flag = True
        return flag    
    

    def __generate_big_simple_number(self) -> int:
        """ 
            Генерация большого простого числа с помощью Решета Эратосфена
            - фильтруются простые числа из списка 10^6 натуральных чисел (для ускорения уменьшить степень)
            - берутся последние 10 элементов (для ускорения уменьшить число элементов)
            - фильтруются числа и остаются только те, которые при делении на 4 в остатке дают 3
            - из оставшихся чисел выбирается одно рандомным образом
        """
        counter: int = (10 ** 6)
        primes: list[int] = set(range(1, counter, 2))
        sieve = [True] * counter
        for i in range(3, int(math.sqrt(counter)) + 1, 2):
            if sieve[i]:
                sieve[i*i::2*i] = [False] * ((counter-i*i-1) // (2*i)+1)
            
        primes: list[int] = [i for i in range(3, counter, 2) if sieve[i]]
        primes: list[int] = primes[len(primes) - 10000: len(primes)]
        primes: list[int] = [el for el in primes if el % 4 == 3]
        #randindex: int = random.randint(0, len(primes) - 1)
        randindex: int = 15
        return primes[randindex]
