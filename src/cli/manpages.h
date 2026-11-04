#pragma once

// Long-form help for one command (description, options, example run with
// representative output), or nullptr if it has none. NAME/USAGE are
// printed by the CLI from its own command table.
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
//   DESCRIPTION
//       What it does and the context needed to use it (what must be set up
//       first, what counts as a "hit", any important limitation). A few
//       short lines - not one terse sentence.
//
//   OPTIONS            (for flag/positional commands)
//     -or-
//   SUBCOMMANDS        (for "<cmd> on|off|status"-style commands)
//       Each argument/flag/subcommand, aligned, one per line, with its
//       default where there is one.
//
//   EXAMPLE  (or EXAMPLES)
//       One or more real invocations, each shown as a 'root@espjack#'
//       prompt line followed by that command's ACTUAL output - the same
//       columns/labels the command really prints, so the help doubles as a
//       sample of what to expect. Never leave a command showing only its
//       usage line with no example output.
//
// Optional trailing sections (NOTES, CONFIG FILE, ...) may follow EXAMPLES.
//
// To add a command: register it in the COMMANDS[] table (name, usage, desc)
// AND add a matching manPage() entry in manpages.cpp following the layout
// above. A command with no manPage() entry still works but only shows
// NAME/USAGE - every new command should ship a full page.
// -----------------------------------------------------------------------
