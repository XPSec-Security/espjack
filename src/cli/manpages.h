#pragma once

// Option/subcommand listing for one command, or nullptr if it has none.
// NAME/USAGE are printed by the CLI from its own command table.
const char *manPage(const char *name);

// -----------------------------------------------------------------------
// -h / help standard  (every command must follow this)
// -----------------------------------------------------------------------
// Running "<cmd> -h" (or "help <cmd>") prints, in this order:
//
//   NAME
//       <cmd> - <one-line description>          (from the command table)
//
//   USAGE
//       <usage string>                          (from the command table)
//
//   <manPage(cmd) body, defined in manpages.cpp:>
//
//   OPTIONS            (for flag/positional commands)
//     -or-
//   SUBCOMMANDS        (for "<cmd> on|off|status"-style commands)
//       Each argument/flag/subcommand, aligned, one per line, with its
//       default where there is one.
//
// That is all: no DESCRIPTION, no EXAMPLES and no NOTES in the firmware.
// The full documentation, with a description and example output for every
// command, is the GitHub wiki:
//   https://github.com/XPSec-Security/espjack/wiki
//
// To add a command: register it in the COMMANDS[] table (name, usage, desc)
// and, if it takes options or subcommands, add a matching manPage() entry
// in manpages.cpp. A command with no entry shows only NAME/USAGE. Also add
// its page to the wiki.
// -----------------------------------------------------------------------
