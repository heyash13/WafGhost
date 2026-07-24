from abc import ABC, abstractmethod
from typing import List
from ..prober import BlockMap

class BaseMutator(ABC):
    """
    Abstract base class for all payload mutators.
    """

    @abstractmethod
    def mutate(self, payload: str, block_map: BlockMap) -> List[str]:
        """
        Takes a base payload and a BlockMap of allowed/blocked tokens,
        and returns a list of candidate mutated payloads.
        """
        pass
