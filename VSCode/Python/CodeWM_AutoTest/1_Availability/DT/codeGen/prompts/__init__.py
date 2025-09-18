# re-export language namespaces for convenient access: prompts.java, prompts.python
from . import java, python  # noqa: F401

__all__ = ["java", "python"]