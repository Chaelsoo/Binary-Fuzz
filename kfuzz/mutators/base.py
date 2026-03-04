from abc import ABC, abstractmethod


class Mutator(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def mutate(self, data: bytes, max_mutations: int = 16) -> list[bytes]: ...
