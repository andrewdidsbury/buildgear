/*
 * This file is part of Build Gear.
 *
 * Copyright (c) 2011-2013  Martin Lund
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "config.h"
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "buildgear/config.h"
#include "buildgear/options.h"
#include "buildgear/cursor.h"

void COptions::Parse(int argc, char *argv[])
{
   int option,i;
   string command;

   /* Print usage help if no arguments are provided */
   if (argc == 1)
   {
      COptions::ShowHelp(argv);
      exit(EXIT_SUCCESS);
   }

   // Save cmdline
   for (i = 0; i < argc; i++)
   {
      Config.cmdline += argv[i];
      Config.cmdline += " ";
   }

   // Save second argument (assumed to be COMMAND)
   command = argv[1];

   // getopt_long stores the option index here
   int option_index = 0;

   // Skip ahead past command
   optind = 2;

   // Help command
   if (command == "help")
   {
      // If a command is specified, show help for that
      if (argc > 2)
      {
         string help_command;

         help_command = argv[2];

         // The execlp function will exit, so we need to restore cursor
         Cursor.restore();

         if (help_command == "download")
            execlp("man", "man", "buildgear-download", NULL);
         else if (help_command == "build")
            execlp("man", "man", "buildgear-build", NULL);
         else if (help_command == "clean")
            execlp("man", "man", "buildgear-clean", NULL);
         else if (help_command == "show")
            execlp("man", "man", "buildgear-show", NULL);
         else if (help_command == "init")
            execlp("man", "man", "buildgear-init", NULL);
         else
            COptions::ShowHelp(argv);
      } else
         COptions::ShowHelp(argv);

      exit(EXIT_SUCCESS);
   }

   // Download command
   else if (command == "download")
   {
      Config.download = true;

      // Parse download OPTIONS
      static struct option long_options[] =
      {
         {"all", no_argument, 0, 'a'},
         {0,     0,           0,  0 }
      };

      option = getopt_long (argc, argv, "", long_options, &option_index);
      while( option != -1 )
      {
         switch( option )
         {
            case 'a':
               Config.all = true;
               break;
            default:
               exit(EXIT_FAILURE);
               break;
         }
         option = getopt_long (argc, argv, "", long_options, &option_index);
      }
   }
   // Build command
   else if (command == "build")
   {
      Config.build = true;

      // Parse build OPTIONS
      static struct option long_options[] =
		{
         {"keep-work",        no_argument, 0, 'w'},
         {"update-checksum",  no_argument, 0, 'c'},
         {"update-footprint", no_argument, 0, 'f'},
         {"no-strip",         no_argument, 0, 's'},
         {"all",              no_argument, 0, 'a'},
         {"no-fakeroot",      no_argument, 0, 'n'},
         {"load-chart",       no_argument, 0, 'l'},
         {0,                  0,           0,  0 }
		};

      option = getopt_long (argc, argv, "", long_options, &option_index);
      while( option != -1 )
      {
         switch( option )
         {
            case 'w':
               Config.keep_work = true;
               break;
            case 'c':
               Config.update_checksum = "yes";
               break;
            case 'f':
               Config.update_footprint = "yes";
               break;
            case 's':
               Config.no_strip = "yes";
               break;
            case 'a':
               Config.all = true;
               break;
            case 'n':
               Config.no_fakeroot = true;
               break;
            case 'l':
               Config.load_chart = true;
               break;
            default:
               exit(EXIT_FAILURE);
               break;
         }
         option = getopt_long (argc, argv, "", long_options, &option_index);
      }
   }
   // Clean command
   else if (command == "clean")
   {
      Config.clean = true;

      // Parse clean OPTIONS
      static struct option long_options[] =
      {
         {"all",        no_argument, 0, 'a'},
         {"footprint",  no_argument, 0, 'f'},
         {"checksum",   no_argument, 0, 'c'},
         {0,            0,           0,  0 }
      };

      option = getopt_long (argc, argv, "", long_options, &option_index);
      while( option != -1 )
      {
         switch( option )
         {
            case 'a':
               Config.all = true;
               break;
            case 'f':
               Config.footprint = true;
               break;
            case 'c':
               Config.checksum = true;
               break;
            default:
               exit(EXIT_FAILURE);
               break;
         }
		option = getopt_long (argc, argv, "", long_options, &option_index);
      }
   }
   // Show command
   else if (command == "show")
   {
      Config.show = true;

      // Parse show OPTIONS
      static struct option long_options[] =
      {
         {"build-order",         no_argument, 0, 'o'},
         {"download-order",      no_argument, 0, 'd'},
         {"dependency",          no_argument, 0, 'c'},
         {"readme",              no_argument, 0, 'r'},
         {"log",                 no_argument, 0, 'l'},
         {"log-tail",            no_argument, 0, 't'},
         {"log-mismatch",        no_argument, 0, 'm'},
         {"version",             no_argument, 0, 'v'},
         {"footprint",           no_argument, 0, 'f'},
         {"checksum",            no_argument, 0, 's'},
         {"buildfile",           no_argument, 0, 'b'},
         {"manifest",            no_argument, 0, 'p'},
         {"manifest-xml",        no_argument, 0, 'x'},
         //{"manifest-html",       no_argument, 0, 'h'},
         {0,                     0,           0,  0 }
      };

      option = getopt_long (argc, argv, "", long_options, &option_index);
      while( option != -1 )
      {
         switch( option )
         {
            case 'o':
               Config.build_order = true;
               break;
            case 'd':
               Config.download_order = true;
               break;
            case 'c':
               Config.dependency_circle = true;
               break;
            case 'r':
               Config.readme = true;
               break;
            case 'l':
               Config.log = true;
               break;
            case 't':
               Config.log = true;
               Config.log_tail = true;
               break;
            case 'm':
               Config.log = true;
               Config.mismatch = true;
               break;
            case 'v':
               Config.show_version = true;
               break;
            case 'f':
               Config.footprint = true;
               break;
            case 's':
               Config.checksum = true;
               break;
            case 'b':
               Config.buildfile = true;
               break;
            case 'p':
               Config.manifest_plain_text = true;
               break;
            case 'x':
               Config.manifest_xml = true;
               break;
            //case 'h': TODO
            //   Config.manifest_html = true;
            //   break;
            default:
               exit(EXIT_FAILURE);
               break;
         }
         option = getopt_long (argc, argv, "", long_options, &option_index);
      }
   }
   // Init command
   else if (command == "init")
   {
      Config.init = true;

      // Parse init OPTIONS
      static struct option long_options[] =
      {
         {"buildfile",  no_argument, 0, 'b'},
         {0,            0,           0,  0 }
      };

      option = getopt_long (argc, argv, "", long_options, &option_index);
      while( option != -1 )
      {
         switch( option )
         {
            case 'b':
               Config.buildfile = true;
               break;
            default:
               exit(EXIT_FAILURE);
         }
         option = getopt_long (argc, argv, "", long_options, &option_index);
      }
   }
   else if (command == "config")
   {
      Config.config = true;

      // Parse config OPTIONS
      static struct option long_options[] =
      {
         {"global",  no_argument, 0, 'g'},
         {"unset",   no_argument, 0, 'u'},
         {"list",    no_argument, 0, 'l'},
         {0,         0,           0,  0 }
      };

      option = getopt_long (argc, argv, "", long_options, &option_index);
      while( option != -1 )
      {
         switch( option )
         {
            case 'g':
               Config.global = true;
               break;
            case 'u':
               Config.unset = true;
               break;
            case 'l':
               Config.blist = true;
               break;
            default:
               exit(EXIT_FAILURE);
               break;
         }

         option = getopt_long (argc, argv, "", long_options, &option_index);
      }

      if (optind < argc)
      {
         string option;
         size_t pos;

         option = argv[optind++];

         // Detect if the option is given as key=value
         pos = option.find("=");
         if (pos != string::npos)
         {
            Config.key = option.substr(0,pos);
            Config.value = option.substr(pos + 1);
         } else
         {
            Config.key = option;
            if (optind < argc)
               Config.value = argv[optind++];
         }
      } else {
         if (!Config.blist)
         {
            cout << "\nError: Please specify an option and a value\n";
            exit(EXIT_FAILURE);
         }
      }
   }
   // No-command
   else
   {
      // No command provided so we don't skip ahead
      optind = 1;

      // Parse OPTIONS
      static struct option long_options[] =
         {
            {"version", no_argument, 0, 'v'},
            {"help",    no_argument, 0, 'h'},
            {0,         0,           0,  0 }
         };

      option = getopt_long (argc, argv, "", long_options, &option_index);
      while( option != -1 )
      {
         switch( option )
         {
            case 'v':
               COptions::ShowVersion();
               exit(EXIT_SUCCESS);
               break;
            case 'h':
               COptions::ShowHelp(argv);
               exit(EXIT_SUCCESS);
               break;
            default:
               exit(EXIT_FAILURE);
               break;
         }
         option = getopt_long (argc, argv, "", long_options, &option_index);
      }
      COptions::ShowHelp(argv);
      exit(EXIT_SUCCESS);
   }

   // Handle remaining options (non '--', '-' options)
   if (optind < argc)
   {
      // Get NAME of build
      Config.name = argv[optind++];

      // Create name stripped from any cross/ or native/ parts
      Config.name_stripped = Config.name;
      size_t pos = Config.name_stripped.rfind("/");
      if (pos != string::npos)
         Config.name_stripped.erase(0,++pos);

      if (optind < argc)
      {
         // Warn if too many arguments
         cout <<  "Too many arguments: ";
         while (optind < argc)
            cout << argv[optind++] << " ";
         cout << endl;
         exit(EXIT_FAILURE);
      }
   }
}

void COptions::ShowHelp(char *argv[])
{
   cout << "Usage: " << argv[0] << " [--help] [--version] <command> [<options>] [build name]\n";
   cout << "\n";
   cout << "  --help                  Display help\n";
   cout << "  --version               Display version\n";
   cout << "\n";
   cout << "Commands:\n";
   cout << "  download                Download source files\n";
   cout << "  build                   Build\n";
   cout << "  clean                   Clean\n";
   cout << "  show                    Show various information\n";
   cout << "  init                    Create empty build area\n";
   cout << "  config                  Configure tool options\n";
   cout << "\n";
   cout << "Download options:\n";
   cout << "  --all                   Download source of all builds or build dependencies\n";
   cout << "\n";
   cout << "Build options:\n";
   cout << "  --keep-work             Do not delete work files\n";
   cout << "  --update-checksum       Update source checksum\n";
   cout << "  --update-footprint      Update footprint\n";
   cout << "  --no-strip              Do not strip libraries and executables\n";
   cout << "  --no-fakeroot           Do not use fakeroot\n";
   cout << "  --all                   Apply to all build dependencies\n";
   cout << "  --load-chart            Generate load chart\n";
   cout << "\n";
   cout << "Clean options:\n";
   cout << "  --footprint             Only clean footprint\n";
   cout << "  --checksum              Only clean checksum\n";
   cout << "  --all                   Apply for all builds or build dependencies\n";
   cout << "\n";
   cout << "Show options:\n";
   cout << "  --build-order           Show build order\n";
   cout << "  --download-order        Show download order\n";
   cout << "  --dependency            Create dependency graph\n";
   cout << "  --readme                Show buildfiles readme\n";
   cout << "  --version               Show build version\n";
   cout << "  --log                   Show build log\n";
   cout << "  --log-tail              Show build log (tailed)\n";
   cout << "  --log-mismatch          Show build log mismatches\n";
   cout << "  --footprint             Show build footprint\n";
   cout << "  --checksum              Show build checksum\n";
   cout << "  --manifest              Create plain text manifest\n";
   cout << "  --manifest-xml          Create XML manifest\n";
   cout << "  --buildfile             Show expanded buildfile\n";
   cout << "\n";
   cout << "Init options:\n";
   cout << "  --buildfile             Create a Buildfile from template\n";
   cout << "\n";
   cout << "Config options:\n";
   cout << "  --global                Apply to global configuration\n";
   cout << "  --unset                 Unset setting (revert to default)\n";
   cout << "  --list                  List current settings\n";
   cout << "\n";
   cout << "See buildgear help <command> for help on a specific command\n";
}

void COptions::ShowVersion(void)
{
   cout << "Build Gear " << VERSION << "\n";
   cout << "Copyright (c) 2011-2014 Martin Lund\n";
   cout << "Copyright (c) 2020 Andrew Didsbury\n";
   cout << "\n";
   cout << "License GPLv2: GNU GPL version 2 or later <http://gnu.org/licenses/gpl-2.0.html>.\n";
   cout << "This is free software: you are free to change and redistribute it.\n";
   cout << "There is NO WARRANTY, to the extent permitted by law.\n";
}
