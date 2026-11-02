import re


class ProofPolicyError(ValueError):
    pass


def active_text(text):
    """Preserve token positions while removing nested comments and strings."""
    result = list(text)
    depth = 0
    quoted = False
    escaped = False
    position = 0
    while position < len(text):
        char = text[position]
        pair = text[position:position + 2]
        if depth:
            if pair in ('(*', '*)'):
                depth += 1 if pair == '(*' else -1
                result[position:position + 2] = '  '
                position += 2
                continue
            result[position] = '\n' if char == '\n' else ' '
        elif quoted:
            result[position] = '\n' if char == '\n' else ' '
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif pair == '(*':
            depth = 1
            result[position:position + 2] = '  '
            position += 2
            continue
        elif char == '"':
            quoted = True
            result[position] = ' '
        position += 1
    if depth or quoted:
        raise ProofPolicyError('Unterminated comment or string in proof source.')
    return ''.join(result)


def check_source(text, allowed_axioms=()):
    code = active_text(text)
    forbidden = re.search(r'\b(?:admit|admitted|abort|pragma)\b', code)
    if forbidden:
        line = code[:forbidden.start()].count('\n') + 1
        raise ProofPolicyError(f'Unchecked proof directive {forbidden[0]} at line {line}.')
    axioms = re.findall(r'\baxiom\s+([A-Za-z_][A-Za-z0-9_\x27]*)', code)
    if len(axioms) != len(re.findall(r'\baxiom\b', code)):
        raise ProofPolicyError('Unsupported axiom declaration syntax.')
    if set(axioms) != set(allowed_axioms) or len(axioms) != len(set(axioms)):
        raise ProofPolicyError('Active axiom declarations do not match the reviewed manifest.')
