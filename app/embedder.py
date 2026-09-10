import os
from collections.abc import Sequence
from typing import Protocol


class Embedder(Protocol):
    @property
    def dimensions(self) -> int: ...

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class FastEmbedder:
    """Lazy local embedder so importing the API never downloads a model."""

    def __init__(self, model_name: str, dimensions: int = 384) -> None:
        self.model_name = model_name
        self._dimensions = dimensions
        self._model = None

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if self._model is None:
            from fastembed import TextEmbedding

            self._model = TextEmbedding(
                model_name=self.model_name,
                cache_dir=os.environ.get("FASTEMBED_CACHE_PATH"),
            )
        return [vector.tolist() for vector in self._model.embed(list(texts))]


class DeterministicEmbedder:
    """Small deterministic implementation intended for tests and local demos."""

    def __init__(self, dimensions: int = 8) -> None:
        self._dimensions = dimensions

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        vectors = []
        for text in texts:
            vector = [0.0] * self.dimensions
            for index, byte in enumerate(text.lower().encode()):
                vector[index % self.dimensions] += (byte % 31) / 31
            magnitude = sum(value * value for value in vector) ** 0.5 or 1
            vectors.append([value / magnitude for value in vector])
        return vectors
