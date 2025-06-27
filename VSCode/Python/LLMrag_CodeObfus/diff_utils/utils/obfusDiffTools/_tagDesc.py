from .renameEnt import *
from .reposVarDecl import *
from enum import Enum

class ObfusType(Enum):
    tag1_1 = {
        "id": "1-1",
        "desc": "Function nameable entity randomization renaming.",
        "content": content_tag1_1,
        "constraints": constraints_tag1_1,
        "typical_changes": typical_changes_tag1_1,
        "algorithm": algorithm_tag1_1,
    }
    
    tag1_2 = {
        "id": "1-2",
        "desc": "Randomized repositioning of variable declarations and initializations strictly within their lexical scope. For each variable, the declaration must appear before its initialization, and both must precede the variable's first use in the control flow. This process preserves semantic correctness while disrupting variable lifecycle locality.", 
        "content": content_tag1_2,
        "constraints": constraints_tag1_2,
        "typical_changes": typical_changes_tag1_2,
        "algorithm": algorithm_tag1_2,
    }
    
    @property
    def desc(self):
        return self.value["desc"]
    
    @property
    def content(self):
        return self.value["content"]
    
    @property
    def constraints(self):
        return self.value["constraints"]
    
    @property
    def typical_changes(self):
        return self.value["typical_changes"]
    
    @property
    def algorithm(self):
        return self.value["algorithm"]