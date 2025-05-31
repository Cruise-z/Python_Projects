from tree_sitter import Language, Parser

class WParser:
    def __init__(self, language):
        self.language = language
        self.parser = Parser()
        self.parser.set_language(Language('build/languages.so', language))

    def get_language(self):
        return self.language