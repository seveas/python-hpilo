#!/usr/bin/python

from utils import *

class LanguageTests(IloTestCase):
    def test_languages(self, ilo):
        ilo.set_language(ilo.get_language()['lang_id'])

if __name__ == '__main__':
    unittest.main()
