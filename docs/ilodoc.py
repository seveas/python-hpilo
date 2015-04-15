from docutils.parsers.rst import Directive
from docutils import nodes
from sphinx.util.nodes import set_source_info
import os
import re
import hpilo

def setup(app):
    app.add_directive('ilo_output', OutputDirective)

class OutputDirective(Directive):
    required_arguments = 1
    optional_arguments = 0

    def run(self):
        method = self.arguments[0]
        if '#' in method:
            method, suffix = method.split('#')
            suffix = '_' + suffix
        else:
            suffix = ''
        assert re.match('^[a-zA-Z][a-zA-Z0-9_]*$', method)
        srcdir = self.state.document.settings.env.srcdir
        with open(os.path.join(srcdir, 'output', method + suffix)) as fd:
            content = fd.read()
        if '\n\n' in content:
            params, result = content.split('\n\n')
            params = ', '.join(params.split('\n'))
        else:
            params, result = '', content

        out = ">>> ilo.%s(%s)\n%s" % (method, params, result)
        literal = nodes.literal_block(out, out)
        literal['language'] = 'python'
        set_source_info(self, literal)
        self.state.parent.children[-1].children[-1].append(literal)
        return []
