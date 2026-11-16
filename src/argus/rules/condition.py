"""Parser and evaluator for the rule condition language.

Supported grammar::

    condition   = or_expr [ "|" "count" "(" ")" comparator integer ]
    or_expr     = and_expr { "or" and_expr }
    and_expr    = unary { "and" unary }
    unary       = "not" unary | "(" or_expr ")" | quantifier | selection
    quantifier  = ("1" | "any" | "all") "of" ( "them" | selector )
    selector    = name | name "*"

``1 of selection*`` means any selection whose name begins with ``selection``.
``all of them`` requires every selection in the rule to match. ``all of
selection*`` requires every matching selection. This is stricter than Sigma's
"one or more" semantics for ``all of them``; the behaviour is documented.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

COMPARATORS = {">=": "gte", ">": "gt", "<=": "lte", "<": "lt", "==": "eq"}

_TOKEN_RE = re.compile(
    r"""
    (?P<space>\s+)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<pipe>\|)
  | (?P<op>>=|<=|==|>|<)
  | (?P<number>\d+)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_.\-]*\*?)
  | (?P<other>.)
    """,
    re.VERBOSE,
)


class ConditionError(ValueError):
    """Raised when a condition cannot be parsed or references unknown selections."""

    def __init__(self, message: str, expression: str = "", position: int | None = None) -> None:
        if position is not None:
            message = f"{message} at position {position}"
        if expression:
            message = f"{message} in condition {expression!r}"
        super().__init__(message)
        self.expression = expression
        self.position = position


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    position: int


@dataclass(frozen=True)
class ThresholdSpec:
    op: str
    count: int


class Node:
    """Base class for condition AST nodes."""

    def evaluate(self, matches: dict[str, bool]) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def selections(self, names: Iterable[str]) -> set[str]:
        raise NotImplementedError

    def describe(self) -> str:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass(frozen=True)
class SelectionRef(Node):
    name: str

    def evaluate(self, matches: dict[str, bool]) -> bool:
        return bool(matches.get(self.name, False))

    def selections(self, names: Iterable[str]) -> set[str]:
        return {self.name}

    def describe(self) -> str:
        return self.name


@dataclass(frozen=True)
class AnyOf(Node):
    prefix: str  # empty means all selections ("them")

    def evaluate(self, matches: dict[str, bool]) -> bool:
        return any(matches.get(name, False) for name in self._names(matches))

    def selections(self, names: Iterable[str]) -> set[str]:
        concrete = _filter_names(names, self.prefix)
        if not concrete:
            target = "them" if not self.prefix else f"{self.prefix}*"
            raise ConditionError(f"selector {target!r} matches no selections")
        return concrete

    def _names(self, matches: dict[str, bool]) -> list[str]:
        return _filter_names(matches.keys(), self.prefix)

    def describe(self) -> str:
        return f"any of {self.prefix + '*' if self.prefix else 'them'}"


@dataclass(frozen=True)
class AllOf(Node):
    prefix: str

    def evaluate(self, matches: dict[str, bool]) -> bool:
        names = self._names(matches)
        return bool(names) and all(matches.get(name, False) for name in names)

    def selections(self, names: Iterable[str]) -> set[str]:
        concrete = _filter_names(names, self.prefix)
        if not concrete:
            target = "them" if not self.prefix else f"{self.prefix}*"
            raise ConditionError(f"selector {target!r} matches no selections")
        return concrete

    def _names(self, matches: dict[str, bool]) -> list[str]:
        return _filter_names(matches.keys(), self.prefix)

    def describe(self) -> str:
        return f"all of {self.prefix + '*' if self.prefix else 'them'}"


@dataclass(frozen=True)
class Not(Node):
    child: Node

    def evaluate(self, matches: dict[str, bool]) -> bool:
        return not self.child.evaluate(matches)

    def selections(self, names: Iterable[str]) -> set[str]:
        return self.child.selections(names)

    def describe(self) -> str:
        return f"not ({self.child.describe()})"


@dataclass(frozen=True)
class And(Node):
    left: Node
    right: Node

    def evaluate(self, matches: dict[str, bool]) -> bool:
        return self.left.evaluate(matches) and self.right.evaluate(matches)

    def selections(self, names: Iterable[str]) -> set[str]:
        return self.left.selections(names) | self.right.selections(names)

    def describe(self) -> str:
        return f"({self.left.describe()} and {self.right.describe()})"


@dataclass(frozen=True)
class Or(Node):
    left: Node
    right: Node

    def evaluate(self, matches: dict[str, bool]) -> bool:
        return self.left.evaluate(matches) or self.right.evaluate(matches)

    def selections(self, names: Iterable[str]) -> set[str]:
        return self.left.selections(names) | self.right.selections(names)

    def describe(self) -> str:
        return f"({self.left.describe()} or {self.right.describe()})"


@dataclass(frozen=True)
class ParsedCondition:
    ast: Node
    threshold: ThresholdSpec | None
    expression: str

    def evaluate(self, matches: dict[str, bool]) -> bool:
        return self.ast.evaluate(matches)

    def resolve(self, selection_names: Iterable[str]) -> set[str]:
        return self.ast.selections(list(selection_names))


def _filter_names(names: Iterable[str], prefix: str) -> set[str]:
    concrete = set(names)
    if not prefix:
        return concrete
    return {name for name in concrete if name.startswith(prefix)}


def tokenize(expression: str) -> list[Token]:
    if not expression or not expression.strip():
        raise ConditionError("condition is empty", expression)
    tokens: list[Token] = []
    for match in _TOKEN_RE.finditer(expression):
        kind = match.lastgroup or "other"
        value = match.group(0)
        if kind == "space":
            continue
        if kind == "other":
            raise ConditionError(f"unexpected character {value!r}", expression, match.start())
        tokens.append(Token(kind=kind, value=value, position=match.start()))
    return tokens


class _Parser:
    def __init__(self, expression: str) -> None:
        self.expression = expression
        self.tokens = tokenize(expression)
        self.index = 0

    def parse(self) -> ParsedCondition:
        node = self._parse_or()
        threshold = None
        if self._peek_kind("pipe"):
            threshold = self._parse_aggregation()
        if self._peek() is not None:
            token = self._peek()
            raise ConditionError(
                f"unexpected token {token.value!r}", self.expression, token.position
            )
        return ParsedCondition(ast=node, threshold=threshold, expression=self.expression)

    def _parse_or(self) -> Node:
        node = self._parse_and()
        while self._match_keyword("or"):
            node = Or(node, self._parse_and())
        return node

    def _parse_and(self) -> Node:
        node = self._parse_unary()
        while self._match_keyword("and"):
            node = And(node, self._parse_unary())
        return node

    def _parse_unary(self) -> Node:
        if self._match_keyword("not"):
            return Not(self._parse_unary())
        if self._peek_kind("lparen"):
            self._advance()
            node = self._parse_or()
            self._expect_kind("rparen", "expected closing parenthesis")
            return node
        token = self._peek()
        if token is None:
            raise ConditionError(
                "unexpected end of condition; expected a selection", self.expression
            )
        if token.kind == "number":
            if token.value != "1":
                raise ConditionError(
                    "only '1 of ...' is supported", self.expression, token.position
                )
            self._advance()
            self._expect_keyword("of", "expected 'of' after '1'")
            return self._parse_quantified(any_mode=True)
        if token.kind == "ident":
            lowered = token.value.lower()
            if lowered in {"any", "all"}:
                self._advance()
                self._expect_keyword("of", f"expected 'of' after {token.value!r}")
                return self._parse_quantified(any_mode=lowered == "any")
            if lowered in {"and", "or", "not", "of", "them"}:
                raise ConditionError(
                    f"unexpected keyword {token.value!r}; expected a selection name",
                    self.expression,
                    token.position,
                )
            self._advance()
            return SelectionRef(token.value)
        raise ConditionError(
            f"unexpected token {token.value!r}; expected a selection name or '('",
            self.expression,
            token.position,
        )

    def _parse_quantified(self, *, any_mode: bool) -> Node:
        token = self._peek()
        if token is None or token.kind != "ident":
            raise ConditionError("expected 'them' or a selector after 'of'", self.expression)
        self._advance()
        value = token.value
        if value.lower() == "them":
            prefix = ""
        elif value.endswith("*"):
            prefix = value[:-1]
            if not prefix:
                raise ConditionError(
                    "selector prefix must not be empty", self.expression, token.position
                )
            return AnyOf(prefix=prefix) if any_mode else AllOf(prefix=prefix)
        else:
            return SelectionRef(value)
        return AnyOf(prefix=prefix) if any_mode else AllOf(prefix=prefix)

    def _parse_aggregation(self) -> ThresholdSpec:
        self._expect_kind("pipe", "expected '|'")
        token = self._peek()
        if token is None or token.kind != "ident" or token.value.lower() != "count":
            raise ConditionError("expected 'count()' after '|'", self.expression)
        self._advance()
        if self._peek_kind("lparen"):
            self._advance()
            self._expect_kind("rparen", "expected ')' after 'count('")
        operator_token = self._peek()
        if operator_token is None or operator_token.kind != "op":
            raise ConditionError("expected a comparison after count()", self.expression)
        self._advance()
        number_token = self._peek()
        if number_token is None or number_token.kind != "number":
            raise ConditionError(
                "expected a threshold number after the comparison", self.expression
            )
        self._advance()
        count = int(number_token.value)
        if count <= 0:
            raise ConditionError("threshold count must be greater than zero", self.expression)
        return ThresholdSpec(op=COMPARATORS[operator_token.value], count=count)

    def _peek(self) -> Token | None:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def _peek_kind(self, kind: str) -> bool:
        token = self._peek()
        return token is not None and token.kind == kind

    def _advance(self) -> Token:
        token = self.tokens[self.index]
        self.index += 1
        return token

    def _match_keyword(self, keyword: str) -> bool:
        token = self._peek()
        if token is not None and token.kind == "ident" and token.value.lower() == keyword:
            self.index += 1
            return True
        return False

    def _expect_keyword(self, keyword: str, message: str) -> None:
        if not self._match_keyword(keyword):
            token = self._peek()
            position = token.position if token else len(self.expression)
            raise ConditionError(message, self.expression, position)

    def _expect_kind(self, kind: str, message: str) -> None:
        if not self._peek_kind(kind):
            token = self._peek()
            position = token.position if token else len(self.expression)
            raise ConditionError(message, self.expression, position)
        self._advance()


def parse_condition(expression: str) -> ParsedCondition:
    """Parse a condition expression into an evaluatable AST."""
    return _Parser(expression).parse()


def evaluate_condition(expression: str, matches: dict[str, bool]) -> bool:
    """Convenience helper used in tests and by callers without a compiled rule."""
    return parse_condition(expression).evaluate(matches)
