#!/usr/bin/env python3

import argparse
import os
import random
import re
import shutil
import string
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import pexpect


class T:
    """Terminal color helper with ANSI escape sequences."""

    red, green, blue, yellow, grey, bold, clear = (
        "\033[31m",
        "\033[32m",
        "\033[34m",
        "\033[33m",
        "\033[90m",
        "\033[1m",
        "\033[0m",
    )


# Allowed executables for shell commands
# Maps command name to actual executable path (relative to this script)
ALLOWED_EXECUTABLES = {
    "age-store.py": "../age-store.py",
}

# Global verbose flag
verbose = False

# Global timeout for shell commands (in seconds)
SHELL_TIMEOUT = 30


def sanitize_test_name(name: str) -> str:
    """Sanitize test name for use as directory name."""
    return re.sub(r"[^a-zA-Z0-9]", "_", name)


def generate_random_suffix() -> str:
    """Generate a 5-character random alphanumeric string."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=5))


def get_terminal_width():
    """Get the terminal width, with fallback."""
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80  # fallback width if terminal size can't be determined


def print_horizontal_rule():
    """Print a horizontal rule spanning the terminal width."""
    width = get_terminal_width()
    print(f"{T.grey}{'─' * width}{T.clear}")


def print_with_left_border(text, border_char="│", border_color=None, text_color=None):
    """Print text with a left border, wrapping lines to terminal width."""
    width = get_terminal_width()
    border_prefix = f"{border_color or ''}{border_char}{T.clear} {text_color or ''}"
    content_width = width - len(border_char) - 1  # Account for border and space

    lines = text.split("\n")
    for line in lines:
        if not line.strip():  # Handle empty lines
            print(f"{border_prefix}{T.clear}")
        elif len(line) <= content_width:
            print(f"{border_prefix}{line}{T.clear}")
        else:
            # Wrap long lines
            while line:
                chunk = line[:content_width]
                line = line[content_width:]
                print(f"{border_prefix}{chunk}{T.clear}")


def show_variable_values(values_dict):
    """Show variable values with grey indentation like command output."""
    for var_name, var_value in values_dict.items():
        print_with_left_border(
            f'{var_name}: "{var_value}"', border_color=T.grey, text_color=T.grey
        )


def verbose_check(description, condition, variables=None):
    """Print assertion description and result, return condition value."""
    if condition:
        print(f"{T.green}▸ {description} ✓{T.clear}")
    else:
        print(f"{T.red}▸ {description} ✗{T.clear}")

    # Show variable values after if provided
    if variables:
        show_variable_values(variables)

    return condition


def setup_test_runs_directory() -> str:
    """Setup and clean the test-runs directory."""
    test_runs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp")

    # Clean existing directory
    if os.path.exists(test_runs_dir):
        shutil.rmtree(test_runs_dir)

    # Create fresh directory
    os.makedirs(test_runs_dir)
    return test_runs_dir


def create_test_directory(base_dir: str, test_name: str) -> str:
    """Create a unique test directory for a test case."""
    sanitized_name = sanitize_test_name(test_name)
    random_suffix = generate_random_suffix()
    test_dir_name = f"{sanitized_name}-{random_suffix}"
    test_dir_path = os.path.join(base_dir, test_dir_name)
    os.makedirs(test_dir_path)
    return test_dir_path


class Tokenizer:
    """Quote-aware tokenizer for parsing command lines into tokens."""

    def __init__(self, line: str):
        self.line = line
        self.pos = 0

    def eof(self) -> bool:
        """Check if we've reached the end of the line."""
        return self.pos >= len(self.line)

    def peek(self) -> Optional[str]:
        """Peek at the current character without consuming it."""
        if self.eof():
            return None
        return self.line[self.pos]

    def skip_whitespace(self):
        """Skip whitespace characters."""
        while not self.eof() and self.line[self.pos].isspace():
            self.pos += 1

    def consume_word(self) -> str:
        """Consume an unquoted word (keyword)."""
        start = self.pos
        while not self.eof() and not self.line[self.pos].isspace():
            self.pos += 1
        return self.line[start : self.pos]

    def consume_quoted(self, quote_char: str) -> str:
        """Consume a quoted string, handling escape sequences."""
        self.pos += 1  # Skip opening quote
        content = ""

        while not self.eof():
            char = self.line[self.pos]
            if char == "\\" and self.pos + 1 < len(self.line):
                # Escaped character
                content += self.line[self.pos + 1]
                self.pos += 2
            elif char == quote_char:
                # Found closing quote
                self.pos += 1  # Skip closing quote
                break
            else:
                content += char
                self.pos += 1

        return content

    def tokenize(self) -> list[str]:
        """
        Tokenize the entire line into a list of strings.
        Handles quoted strings properly by removing quotes and processing escapes.
        """
        tokens: list[str] = []

        while not self.eof():
            self.skip_whitespace()
            if self.eof():
                break

            char = self.peek()
            if char in ['"', "'"]:
                # Quoted string
                content = self.consume_quoted(char)
                tokens.append(content)
            else:
                # Unquoted word
                content = self.consume_word()
                tokens.append(content)

        return tokens


class CommandType(Enum):
    SHELL = "shell"
    ASSERTION = "assertion"
    DSL_ACTION = "dsl_action"
    COMMENT = "comment"


@dataclass
class Command:
    type: CommandType
    token: str  # First token after the prefix
    args: list[str]  # Remaining tokens
    content: list[str]  # Lines following with ".." prefix
    comment: str = ""  # Trailing comment or full comment for COMMENT type
    negated: bool = False  # True if second char was "!"
    line_number: int = 0
    pexpect_interactions: list[tuple[str, str]] = field(
        default_factory=list
    )  # [(action_type, text), ...]

    def to_str(self) -> str:
        """Reconstruct the original line excluding comments"""
        if self.type == CommandType.COMMENT:
            return f"-- {self.comment}"

        prefix = ""
        if self.type == CommandType.SHELL:
            prefix = "$!" if self.negated else "$."
        elif self.type == CommandType.ASSERTION:
            prefix = "?!" if self.negated else "?."
        elif self.type == CommandType.DSL_ACTION:
            prefix = ":."

        parts = [prefix, self.token] + self.args
        return " ".join(parts)


@dataclass
class Stanza:
    name: str
    commands: list[Command]
    line_number: int = 0


@dataclass
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    execution_type: str  # "subprocess" or "pexpect"


class Reader:
    def __init__(self, content: str):
        self.lines = content.splitlines()
        self.position = 0

    def peek(self) -> str:
        """Return the next line without consuming it, raises EOFError if at EOF"""
        if self.position >= len(self.lines):
            raise EOFError("Attempted to peek at EOF")
        return self.lines[self.position]

    def consume(self) -> str:
        """Consume and return the next line, raises EOFError if at EOF"""
        if self.position >= len(self.lines):
            raise EOFError("Attempted to consume line at EOF")
        line = self.lines[self.position]
        self.position += 1
        return line

    def is_eof(self) -> bool:
        return self.position >= len(self.lines)

    def line_number(self) -> int:
        return self.position + 1


class Parser:
    def __init__(self, content: str):
        self.reader = Reader(content)
        self.test_suite = TestSuite()

    def parse(self) -> "TestSuite":
        """Parse the entire DSL content"""
        while not self.reader.is_eof():
            try:
                line = self.reader.peek()
                if not line or line.strip() == "":
                    self.reader.consume()
                    continue

                # Parse test case or snippet
                if line[0] == ">":
                    self.parse_stanza()
                elif line.startswith("--"):
                    # Skip top-level comments
                    self.reader.consume()
                    continue
                else:
                    # Error on unknown lines
                    line_num = self.reader.line_number()
                    raise ValueError(f"Unknown line at {line_num}: {line}")
            except EOFError:
                break

        return self.test_suite

    def parse_stanza(self):
        """Parse from '>@' or '>' to the next '>@' or '>'"""
        start_line_number = self.reader.line_number()
        start_line = self.reader.consume()

        if start_line.startswith(">@"):
            # Snippet definition
            name = start_line[2:].strip()
            commands = self._parse_commands_until_next_stanza()
            stanza = Stanza(name, commands, start_line_number)
            self.test_suite.add_snippet(stanza)
        else:
            # Test case
            name = start_line[1:].strip()
            commands = self._parse_commands_until_next_stanza()
            stanza = Stanza(name, commands, start_line_number)
            self.test_suite.add_test_case(stanza)

    def _parse_commands_until_next_stanza(self) -> list[Command]:
        """Parse commands until we hit the next '>' or EOF"""
        commands = []

        while not self.reader.is_eof():
            try:
                line = self.reader.peek()

                # Skip empty lines
                if line.strip() == "":
                    self.reader.consume()
                    continue

                # Stop at next test case or snippet
                if line[0] == ">":
                    break

                # Parse command
                first_char = line[0]
                if first_char in ["$", "?", ":", "-"]:
                    commands.append(self.parse_command())
                else:
                    # Error on unknown lines
                    line_num = self.reader.line_number()
                    raise ValueError(f"Unknown command at {line_num}: {line}")
            except EOFError:
                break

        return commands

    def parse_command(self) -> Command:
        """Parse a command line and any subsequent '..' content lines"""
        line_number = self.reader.line_number()
        line = self.reader.consume()

        # Handle comments
        if line.startswith("--"):
            comment_text = line[2:].strip()
            return Command(
                type=CommandType.COMMENT,
                token="",
                args=[],
                content=[],
                comment=comment_text,
                line_number=line_number,
            )

        # Parse trailing comment
        comment = ""
        if " -- " in line:
            line, comment = line.split(" -- ", 1)
            comment = comment.strip()

        # Determine command type and negation
        if len(line) < 2:
            raise ValueError(f"Invalid command at line {line_number}: {line}")

        prefix = line[:2]
        negated = prefix[1] == "!"

        if prefix[0] == "$":
            cmd_type = CommandType.SHELL
        elif prefix[0] == "?":
            cmd_type = CommandType.ASSERTION
        elif prefix[0] == ":":
            cmd_type = CommandType.DSL_ACTION
        else:
            raise ValueError(f"Unknown command prefix: {prefix} at line {line_number}")

        # Parse tokens using the tokenizer
        tokenizer = Tokenizer(line[2:].strip())
        tokens = tokenizer.tokenize()

        if not tokens:
            raise ValueError(f"Empty command at line {line_number}")

        token = tokens[0]
        args = tokens[1:] if len(tokens) > 1 else []

        # Parse pexpect interactions for shell commands (lines starting with "$<" or "$>")
        pexpect_interactions = []
        if cmd_type == CommandType.SHELL:
            while not self.reader.is_eof():
                try:
                    next_line = self.reader.peek()
                    if next_line and (
                        next_line.startswith("$<") or next_line.startswith("$>")
                    ):
                        pexpect_line = self.reader.consume()
                        action_type = (
                            "expect" if pexpect_line.startswith("$<") else "sendline"
                        )

                        # Treat the rest of the line as a single string
                        content_text = pexpect_line[2:].strip()
                        if content_text:
                            pexpect_interactions.append((action_type, content_text))
                    else:
                        break
                except EOFError:
                    break

        # Parse content lines (lines starting with "..")
        content = []
        while not self.reader.is_eof():
            try:
                next_line = self.reader.peek()
                if next_line and next_line.startswith(".."):
                    content_line = self.reader.consume()
                    content.append(content_line[2:].strip())
                else:
                    break
            except EOFError:
                break

        return Command(
            type=cmd_type,
            token=token,
            args=args,
            content=content,
            comment=comment,
            negated=negated,
            line_number=line_number,
            pexpect_interactions=pexpect_interactions,
        )


class TestSuite:
    def __init__(self):
        self.test_cases: list[Stanza] = []
        self._snippets: dict[str, Stanza] = {}

    def add_test_case(self, stanza: Stanza):
        self.test_cases.append(stanza)

    def add_snippet(self, stanza: Stanza):
        self._snippets[stanza.name] = stanza

    def get_test_cases(self) -> list[Stanza]:
        return self.test_cases

    def resolve_snippet(self, name: str) -> Optional[Stanza]:
        return self._snippets.get(name)


class TestRunner:
    def __init__(self):
        self.last_process = None
        self.last_stdout = ""
        self.last_stderr = ""
        self.variables: dict[str, str] = {}
        self.temp_files: list[str] = []
        self.test_runs_dir = ""
        self.current_test_dir = ""

    def cleanup(self):
        """Clean up resources"""
        # Files are now isolated in test directories, so no need to clean individual files
        pass

    def run_all_tests(
        self, test_suite: TestSuite, test_filter: Optional[str] = None
    ) -> bool:
        """Run all test cases from the test suite, return True if all passed"""
        passed = 0
        failed_tests = []
        test_cases = test_suite.get_test_cases()
        total = len(test_cases)

        # Beautified header
        print(f"{T.bold}{T.blue}ShellSpec Test Runner{T.clear}")
        print(f"Found {total} test cases and {len(test_suite._snippets)} snippets")
        print()

        # Setup test runs directory
        self.test_runs_dir = setup_test_runs_directory()
        if verbose:
            print(f"Test runs directory: {self.test_runs_dir}")

        def should_run_test(test_num: int, test_name: str) -> bool:
            """Check if test should be run based on filter"""
            if not test_filter:
                return True
            # Check if filter is a number
            if test_filter.isdigit():
                return test_num == int(test_filter)
            # Check substring match
            return test_filter.lower() in test_name.lower()

        try:
            tests_run = 0
            for i, test_case in enumerate(test_cases):
                test_num = i + 1
                if not should_run_test(test_num, test_case.name):
                    continue

                if (
                    tests_run > 0
                ):  # Add horizontal line before each test except the first
                    print()
                    print_horizontal_rule()
                print(
                    f"{T.bold}{T.yellow}[{test_num}/{total}] {test_case.name}{T.clear}"
                )
                if self.run_test_case(test_case, test_suite):
                    print(f"\n{T.bold}{T.green}PASS{T.clear}")
                    passed += 1
                else:
                    print(f"\n{T.bold}{T.red}FAIL{T.clear}")
                    failed_tests.append((test_num, test_case.name))
                tests_run += 1
        finally:
            self.cleanup()

        # Beautified footer
        print()
        print_horizontal_rule()
        print(f"{T.bold}Test Results{T.clear}")
        failed_count = len(failed_tests)
        print(
            f"  {T.green}{passed} passed{T.clear}, {T.red}{failed_count} failed{T.clear} out of {total} tests"
        )

        if failed_tests:
            print(f"\n{T.bold}Failed tests:{T.clear}")
            for test_num, test_name in failed_tests:
                print(f"  {T.red}• [{test_num}] {test_name}{T.clear}")

        print()
        if failed_count == 0:
            print(f"{T.bold}{T.green}All tests passed! ✅{T.clear}")
            return True
        else:
            print(f"{T.bold}{T.red}Some tests failed ❌{T.clear}")
            return False

    def run_stanza(self, stanza: Stanza, test_suite: TestSuite) -> bool:
        """Run a stanza (test case or snippet), return True if passed"""
        try:
            for command in stanza.commands:
                if command.type == CommandType.COMMENT:
                    # Show comment with square bullet like test_runner.py descriptions
                    print(f"\n◼ {command.comment}")
                    continue

                if not self.run_command(command, test_suite):
                    if command.comment:
                        print(f"  Context: {command.comment}")
                    return False

            return True
        except Exception as e:
            print(f"ERROR: {stanza.name} - {e}")
            return False

    def run_test_case(self, test_case: Stanza, test_suite: TestSuite) -> bool:
        """Run a single test case, return True if passed"""
        # Create unique test directory and change to it
        old_cwd = os.getcwd()
        self.current_test_dir = create_test_directory(
            self.test_runs_dir, test_case.name
        )

        try:
            os.chdir(self.current_test_dir)

            return self.run_stanza(test_case, test_suite)
        finally:
            # Always restore original directory
            os.chdir(old_cwd)

    def run_command(self, command: Command, test_suite: TestSuite) -> bool:
        """Run a single command, return True if successful"""
        try:
            if command.type == CommandType.SHELL:
                return self._run_shell_command(command)
            elif command.type == CommandType.ASSERTION:
                return self._run_assertion(command)
            elif command.type == CommandType.DSL_ACTION:
                return self._run_dsl_action(command, test_suite)
            else:
                return True  # Comments are handled in run_test_case
        except Exception as e:
            print(f"Command failed at line {command.line_number}: {e}")
            if command.comment:
                print(f"  Context: {command.comment}")
            return False

    def _run_shell_command(self, command: Command) -> bool:
        """Execute shell command with unified diagnostic output"""
        # Check if the command is allowed
        if command.token not in ALLOWED_EXECUTABLES:
            print(f"Command not allowed: {command.token}")
            print(f"Allowed commands: {list(ALLOWED_EXECUTABLES.keys())}")
            return False

        # Get the actual executable path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        exe_path = ALLOWED_EXECUTABLES[command.token]

        if exe_path.startswith("/"):
            # Absolute path: "/usr/bin/age"
            executable_path = exe_path
        elif "/" in exe_path:
            # Relative path: "../../age-store.py" or "./age"
            executable_path = os.path.join(script_dir, exe_path)
        else:
            # System command: "age", "ls", "python"
            executable_path = exe_path

        # Resolve variables in command arguments
        resolved_args = [self._resolve_value(arg) for arg in command.args]
        cmd_line = [executable_path] + resolved_args
        args_str = " ".join(resolved_args)

        try:
            # Execute command based on whether it has pexpect interactions
            if command.pexpect_interactions:
                # For pexpect commands, print in blue immediately
                print(f"{T.blue}{command.token} {args_str}{T.clear}")
                result = self._run_pexpect_command(command, cmd_line)
            else:
                # Print the command being executed (initial yellow state)
                print(f"{T.yellow}{command.token} {args_str}{T.clear}", end="\r")
                result = self._run_subprocess_command(cmd_line)
                # Determine command color based on exit code for subprocess commands
                command_color = T.green if result.exit_code == 0 else T.red
                print(f"{command_color}{command.token} {args_str}{T.clear}")

            # Store results for assertions
            self.last_stdout = result.stdout
            self.last_stderr = result.stderr

            # Print stderr first if it exists (with yellow border) - only if verbose
            if verbose and result.stderr.strip():
                print_with_left_border(
                    result.stderr.rstrip(), border_color=T.yellow, text_color=T.grey
                )

            # Print stdout if verbose mode is enabled
            if verbose and result.stdout.strip():
                print_with_left_border(
                    result.stdout.rstrip(), border_color=T.grey, text_color=T.grey
                )

            # Check if we expected success or failure and show assertion
            expected_success = not command.negated
            actual_success = result.exit_code == 0

            success_msg = (
                "success (exit 0)" if expected_success else "error (exit non-zero)"
            )
            return verbose_check(success_msg, expected_success == actual_success)

        except Exception as e:
            print(f"{T.red}{command.token} {args_str} - ERROR{T.clear}")
            print(f"  {e}")
            return False

    def _run_subprocess_command(self, cmd_line: list[str]) -> ExecutionResult:
        """Execute command with subprocess and return ExecutionResult"""
        try:
            result = subprocess.run(
                cmd_line, capture_output=True, text=True, timeout=SHELL_TIMEOUT
            )
            return ExecutionResult(
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                execution_type="subprocess",
            )
        except subprocess.TimeoutExpired:
            raise Exception(f"Command timed out: {' '.join(cmd_line)}")
        except FileNotFoundError:
            raise Exception(f"Executable not found: {cmd_line[0]}")

    def _run_pexpect_command(
        self, command: Command, cmd_line: list[str]
    ) -> ExecutionResult:
        """Execute shell command with pexpect interactions and return ExecutionResult"""
        try:
            # Spawn the process with pexpect
            proc = pexpect.spawn(cmd_line[0], cmd_line[1:], timeout=SHELL_TIMEOUT)

            # Process each pexpect interaction
            for action_type, text in command.pexpect_interactions:
                if action_type == "expect":
                    print_with_left_border(
                        f"expect: {text}", border_color=T.grey, text_color=T.grey
                    )
                    proc.expect(text)
                elif action_type == "sendline":
                    print_with_left_border(
                        f"send: {text}", border_color=T.grey, text_color=T.grey
                    )
                    proc.sendline(text)

            # Wait for process to complete and get output
            proc.expect(pexpect.EOF)
            proc.close()

            exit_code = proc.exitstatus or 0
            print_with_left_border(
                f"exit: {exit_code}", border_color=T.grey, text_color=T.grey
            )

            return ExecutionResult(
                exit_code=exit_code,
                stdout=proc.before.decode("utf-8") if proc.before else "",
                stderr="",  # pexpect doesn't separate stderr
                execution_type="pexpect",
            )

        except pexpect.TIMEOUT:
            raise Exception(f"Pexpect command timed out: {' '.join(cmd_line)}")
        except pexpect.EOF as e:
            raise Exception(f"Pexpect: unexpected EOF: {' '.join(cmd_line)}")
        except Exception as e:
            raise Exception(f"Pexpect error: {e}")

    def _run_assertion(self, command: Command) -> bool:
        """Run assertion command"""
        target = command.token

        if target == "stdout":
            return self._assert_stdout_stderr(command, self.last_stdout, "stdout")
        elif target == "stderr":
            return self._assert_stdout_stderr(command, self.last_stderr, "stderr")
        elif target == "file":
            return self._assert_file(command)
        elif target in ["==", "!=", "startswith", "endswith", "contains"]:
            return self._assert_comparison(command)
        else:
            print(f"Unknown assertion target: {target}")
            return False

    def _assert_stdout_stderr(self, command: Command, text: str, target: str) -> bool:
        """Handle stdout/stderr assertions with support for exact content matching"""

        # Check for exact content (from .. lines)
        if command.content:
            expected_content = "\n".join(command.content)
            actual_content = text.strip()
            matches = actual_content == expected_content

            if command.negated:
                msg = f"{target} differs"
            else:
                msg = f"{target} matches exactly"
            expected_result = not matches if command.negated else matches
            result = verbose_check(msg, expected_result)

            if verbose:
                for line in command.content:
                    print(f"{T.grey}│ {line}{T.clear}")

            return result

        # Regular substring check
        if not command.args:
            print(f"Assertion missing arguments: {command.token}")
            return False

        search_text = command.args[0]
        found = search_text in text

        # Create descriptive assertion message
        if command.negated:
            msg = f"{target} lacks '{search_text}'"
        else:
            msg = f"{target} has '{search_text}'"

        expected_result = not found if command.negated else found
        return verbose_check(msg, expected_result)

    def _assert_file(self, command: Command) -> bool:
        """Handle file assertions"""
        if not command.args:
            return False

        file_path = command.args[0]

        # Check if file exists
        exists = os.path.exists(file_path)

        if len(command.args) == 1:
            # Just checking existence
            if command.negated:
                msg = f"file '{file_path}' absent"
            else:
                msg = f"file '{file_path}' exists"
            expected_result = not exists if command.negated else exists
            return verbose_check(msg, expected_result)

        if not exists:
            msg = f"file '{file_path}' exists"
            return verbose_check(msg, command.negated)

        # Check file content
        if len(command.args) == 2:
            search_text = command.args[1]
            with open(file_path, "r") as f:
                content = f.read()
            found = search_text in content

            if command.negated:
                msg = f"file '{file_path}' lacks '{search_text}'"
            else:
                msg = f"file '{file_path}' has '{search_text}'"
            expected_result = not found if command.negated else found
            return verbose_check(msg, expected_result)

        # Check exact content (from .. lines)
        if command.content:
            expected_content = "\n".join(command.content)
            with open(file_path, "r") as f:
                actual_content = f.read().strip()
            matches = actual_content == expected_content

            if command.negated:
                msg = f"file '{file_path}' differs"
            else:
                msg = f"file '{file_path}' matches exactly"
            expected_result = not matches if command.negated else matches
            return verbose_check(msg, expected_result)

        return True

    def _assert_comparison(self, command: Command) -> bool:
        """Handle comparison assertions"""
        if len(command.args) < 2:
            return False

        # Collect variable values for display
        variables = {}
        left_arg = command.args[0]
        right_arg = command.args[1]
        left = self._resolve_value(left_arg, variables)
        right = self._resolve_value(right_arg, variables)

        if command.token == "==":
            result = left == right
            if command.negated:
                msg = f"'{left_arg}' != '{right_arg}'"
            else:
                msg = f"'{left_arg}' == '{right_arg}'"
        elif command.token == "!=":
            result = left != right
            if command.negated:
                msg = f"'{left_arg}' == '{right_arg}'"
            else:
                msg = f"'{left_arg}' != '{right_arg}'"
        elif command.token == "startswith":
            result = left.startswith(right)
            if command.negated:
                msg = f"'{left_arg}' !startswith '{right_arg}'"
            else:
                msg = f"'{left_arg}' startswith '{right_arg}'"
        elif command.token == "endswith":
            result = left.endswith(right)
            if command.negated:
                msg = f"'{left_arg}' !endswith '{right_arg}'"
            else:
                msg = f"'{left_arg}' endswith '{right_arg}'"
        elif command.token == "contains":
            result = right in left
            if command.negated:
                msg = f"'{left_arg}' lacks '{right_arg}'"
            else:
                msg = f"'{left_arg}' contains '{right_arg}'"
        else:
            return False

        expected_result = not result if command.negated else result
        return verbose_check(msg, expected_result, variables)

    def _resolve_value(self, value: str, context: dict = None) -> str:
        """Resolve variable or return literal value"""
        # Handle @variable syntax
        if value.startswith("@"):
            clean_var_name = value[1:]
            if clean_var_name in self.variables:
                resolved_value = self.variables[clean_var_name]
                # Add to context if provided
                if context is not None:
                    context[value] = resolved_value
                return resolved_value
            else:
                print(f"Warning: Undefined variable {value}")
                return value  # Return the original @variable if undefined

        # Return literal value if not a variable
        return value

    def _run_dsl_action(self, command: Command, test_suite: TestSuite) -> bool:
        """Run DSL action command"""
        if command.token == "file":
            return self._create_file(command)
        elif command.token == "stdout":
            return self._store_variable(command, self.last_stdout)
        elif command.token == "stderr":
            return self._store_variable(command, self.last_stderr)
        elif command.token == "@":
            # Invoke snippet
            if not command.args:
                print("Snippet invocation missing snippet name")
                return False
            snippet_name = command.args[0]
            return self._invoke_snippet(snippet_name, test_suite)
        else:
            print(f"Unknown DSL action: {command.token}")
            return False

    def _create_file(self, command: Command) -> bool:
        """Create file with content"""
        if not command.args:
            return False

        file_path = command.args[0]
        mode = int(command.args[1], 8) if len(command.args) > 1 else 0o644

        content = "\n".join(command.content) if command.content else ""

        try:
            # Create directory structure if needed
            dir_path = os.path.dirname(file_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path)

            with open(file_path, "w") as f:
                f.write(content)
            os.chmod(file_path, mode)
            return True
        except Exception as e:
            print(f"Failed to create file {file_path}: {e}")
            return False

    def _store_variable(self, command: Command, value: str) -> bool:
        """Store value in variable"""
        if not command.args:
            return False

        var_name = command.args[0]
        # Variable names must start with @
        if not var_name.startswith("@"):
            print(f"Variable name must start with '@': {var_name}")
            return False

        # Store without the @ prefix
        clean_var_name = var_name[1:]
        if not clean_var_name:
            print("Variable name cannot be empty after '@'")
            return False

        self.variables[clean_var_name] = value.strip()
        return True

    def _invoke_snippet(self, snippet_name: str, test_suite: TestSuite) -> bool:
        """Invoke a snippet"""
        snippet = test_suite.resolve_snippet(snippet_name)
        if not snippet:
            print(f"Unknown snippet: {snippet_name}")
            return False

        return self.run_stanza(snippet, test_suite)


def main():
    global verbose

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="ShellSpec Test Runner")
    parser.add_argument("test_file", help="Test file to run")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print the output of each command",
    )
    parser.add_argument(
        "--test",
        help="Run only tests matching this number or substring of test title",
    )
    args = parser.parse_args()

    # Set global verbose flag
    verbose = args.verbose

    test_file = args.test_file

    try:
        with open(test_file, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Test file not found: {test_file}")
        sys.exit(1)

    # Run tests
    try:
        dsl_parser = Parser(content)
        test_suite = dsl_parser.parse()
        runner = TestRunner()
        success = runner.run_all_tests(test_suite, test_filter=args.test)
    except ValueError as e:
        print(f"Parse error: {e}")
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
